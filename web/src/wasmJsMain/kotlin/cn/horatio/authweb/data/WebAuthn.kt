// 浏览器 WebAuthn 互操作：注册（navigator.credentials.create）与断言（get）。
//
// 对应 Go 端点（cmd/server/web.go）：
//   POST /webauthn/register/options  → CeremonyResponse(publicKey 创建选项)
//   POST /webauthn/register/finish   → PasskeyFinishRequest{ceremonyId, response}
//   POST /webauthn/login/options|finish   （登录仪式，匿名）
//   POST /web/reauth/webauthn/options|finish （重新验证断言）
//
// 形态约定（与 internal/ui/app.js 同一套，凭证 JSON 是 Go 侧 webauthn 库的解析入口）：
// - Go 发来的 publicKey options 里 challenge / user.id / allowCredentials[].id /
//   excludeCredentials[].id 是 base64url 字符串；浏览器 API 只收 ArrayBuffer。
// - 结果 credential 要变回 {id, rawId, type, response:{clientDataJSON, ...}}
//   的 base64url JSON。
//
// **序列化路径（实测决策）**：JS 侧运行时探测 `PublicKeyCredential.toJSON()`
// （Chrome 119+ / Safari 17+，输出同形 base64url JSON）——有就用它，字段更全
// （含 transports / authenticatorAttachment）；没有则回退到手搓序列化（与 app.js
// 的 creationJSON/assertionJSON 逐字段一致，Go 侧 credentialJSON 两种都收）。
// 深度转换全在 @JsFun 的 JS 里做，Kotlin 侧只传/收字符串，不碰 ArrayBuffer。
@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package cn.horatio.authweb.data

import kotlin.js.JsString
import kotlin.js.Promise
import kotlin.js.toJsString
import kotlinx.coroutines.await
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

// 用户取消（NotAllowedError/AbortError）回 null；其余错误 reject 原样抛给调用方。
private const val CRED_JS = """
(optionsJson, create) => {
  const b64urlToBytes = (s) => {
    const b = String(s).replace(/-/g, '+').replace(/_/g, '/');
    const pad = b.length % 4 ? '='.repeat(4 - (b.length % 4)) : '';
    const bin = atob(b + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  };
  const b64url = (buf) => {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const pk = JSON.parse(optionsJson);
  if (typeof pk.challenge === 'string') pk.challenge = b64urlToBytes(pk.challenge);
  if (pk.user && typeof pk.user.id === 'string') pk.user.id = b64urlToBytes(pk.user.id);
  ['allowCredentials', 'excludeCredentials'].forEach(k => {
    if (Array.isArray(pk[k])) pk[k].forEach(c => { if (typeof c.id === 'string') c.id = b64urlToBytes(c.id); });
  });
  const done = create
    ? navigator.credentials.create({ publicKey: pk })
    : navigator.credentials.get({ publicKey: pk });
  return done.then(cred => {
    if (!cred) return null;
    if (typeof cred.toJSON === 'function') return JSON.stringify(cred.toJSON());
    const base = { id: cred.id, rawId: b64url(cred.rawId), type: cred.type };
    if (create) {
      base.response = {
        clientDataJSON: b64url(cred.response.clientDataJSON),
        attestationObject: b64url(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : undefined,
      };
    } else {
      base.response = {
        clientDataJSON: b64url(cred.response.clientDataJSON),
        authenticatorData: b64url(cred.response.authenticatorData),
        signature: b64url(cred.response.signature),
        userHandle: cred.response.userHandle ? b64url(cred.response.userHandle) : undefined,
      };
    }
    base.clientExtensionResults = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};
    return JSON.stringify(base);
  }).catch(e => {
    if (e && (e.name === 'NotAllowedError' || e.name === 'AbortError')) return null;
    throw e;
  });
}
"""

@JsFun(CRED_JS)
private external fun credentialCeremony(optionsJson: JsString, create: Boolean): Promise<JsString?>

/** 注册仪式：PublicKeyCredential 创建选项（CeremonyResponse.publicKey）进出，用户取消/失败回 null。 */
suspend fun createCredential(options: JsonElement): JsonElement? =
    credentialCeremony(options.toString().toJsString(), true).await()?.let {
        Json.parseToJsonElement(it.toString())
    }

/** 断言仪式（登录/重新验证）：PublicKeyCredential 请求选项进出，用户取消/失败回 null。 */
suspend fun getAssertion(options: JsonElement): JsonElement? =
    credentialCeremony(options.toString().toJsString(), false).await()?.let {
        Json.parseToJsonElement(it.toString())
    }

// ---- base64url（无 padding）↔ ByteArray：手写，不依赖平台库 ----

private const val B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

/** ByteArray → base64url（无 padding，WebAuthn/JS-safe 形态）。 */
fun ByteArray.toBase64Url(): String {
    val sb = StringBuilder(size * 4 / 3 + 4)
    var i = 0
    while (i + 2 < size) {
        val n = ((this[i].toInt() and 0xFF) shl 16) or
            ((this[i + 1].toInt() and 0xFF) shl 8) or
            (this[i + 2].toInt() and 0xFF)
        sb.append(B64URL_ALPHABET[(n shr 18) and 63])
        sb.append(B64URL_ALPHABET[(n shr 12) and 63])
        sb.append(B64URL_ALPHABET[(n shr 6) and 63])
        sb.append(B64URL_ALPHABET[n and 63])
        i += 3
    }
    val rem = size - i
    if (rem == 1) {
        val n = (this[i].toInt() and 0xFF) shl 16
        sb.append(B64URL_ALPHABET[(n shr 18) and 63])
        sb.append(B64URL_ALPHABET[(n shr 12) and 63])
    } else if (rem == 2) {
        val n = ((this[i].toInt() and 0xFF) shl 16) or ((this[i + 1].toInt() and 0xFF) shl 8)
        sb.append(B64URL_ALPHABET[(n shr 18) and 63])
        sb.append(B64URL_ALPHABET[(n shr 12) and 63])
        sb.append(B64URL_ALPHABET[(n shr 6) and 63])
    }
    return sb.toString()
}

private fun b64UrlDigit(c: Char): Int = when (c) {
    in 'A'..'Z' -> c - 'A'
    in 'a'..'z' -> c - 'a' + 26
    in '0'..'9' -> c - '0' + 52
    '-' -> 62
    '_' -> 63
    else -> -1
}

/** base64url（可带 padding、可混用标准字母表）→ ByteArray；非法字符抛 IllegalArgumentException。 */
fun String.base64UrlToBytes(): ByteArray {
    val clean = filter { it != '=' }
    val out = ByteArray(clean.length * 3 / 4)
    var acc = 0
    var bits = 0
    var o = 0
    for (c in clean) {
        val d = b64UrlDigit(c)
        if (d < 0) throw IllegalArgumentException("非法 base64url 字符: $c")
        acc = (acc shl 6) or d
        bits += 6
        if (bits >= 8) {
            bits -= 8
            out[o++] = (acc shr bits).toByte()
        }
    }
    return if (o == out.size) out else out.copyOf(o)
}
