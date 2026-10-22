// HTTP 数据层：auth 后端 JSON API 的统一 fetch 封装（同源 cookie 会话）。
//
// 端点契约见 Go 侧 cmd/server/{routes,web}.go 与 internal/protocol/protocol.go：
// 非 2xx 回执体统一为 {"message":"..."}（protocol.ApiError），此处抛 [ApiException]。
// Web 会话靠 HttpOnly cookie（__Host-auth_web）携带，非 GET 请求必须带 X-CSRF-Token
// （值来自可读 cookie，由 SessionStore.refresh 装进 [Api.csrfToken]）。
@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package cn.horatio.authweb.data

import kotlin.js.JsString
import kotlin.js.toJsString
import kotlinx.browser.window
import kotlinx.coroutines.await
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.w3c.fetch.Headers
import org.w3c.fetch.RequestInit

class HttpResponse(val status: Int, val body: String)

/** 服务端业务错误：非 2xx 回执的 message 即 Go 侧写给用户的中文提示。 */
class ApiException(val status: Int, override val message: String) : Exception(message)

/**
 * 解析回执：2xx → 按 [T] 反序列化；非 2xx → 先取 {"message"} 再抛 [ApiException]。
 * 后端所有 JSON 回执都不含未知字段风险，统一 ignoreUnknownKeys。
 */
inline fun <reified T> HttpResponse.json(): T {
    if (status < 200 || status > 299) {
        val message = try {
            Json.decodeFromString<ApiError>(body).message
        } catch (_: Exception) {
            body.ifEmpty { "请求失败（HTTP $status）" }
        }
        throw ApiException(status, message)
    }
    return Api.Json.decodeFromString(body)
}

object Api {
    /** CSRF 令牌，SessionStore.refresh 装载会话后同步；非 GET 请求自动附带。 */
    var csrfToken: String = ""

    @PublishedApi
    internal val Json = Json { ignoreUnknownKeys = true }

    /** 底层请求：GET 不带 body 与 CSRF；其余方法固定附 JSON 头 + CSRF 头。 */
    suspend fun request(method: String, path: String, body: String? = null): HttpResponse {
        val headers = Headers()
        var payload: JsString? = null
        if (method != "GET") {
            headers.append("Content-Type", "application/json")
            headers.append("X-CSRF-Token", csrfToken)
            payload = body?.toJsString()
        }
        val res = window.fetch(path, RequestInit(method = method, headers = headers, body = payload)).await()
        return HttpResponse(res.status.toInt(), res.text().await().toString())
    }

    suspend inline fun <reified T> get(path: String): T = request("GET", path).json()

    suspend inline fun <reified T> post(path: String, bodyJson: String? = null): T =
        request("POST", path, bodyJson).json()

    suspend inline fun <reified T> put(path: String, bodyJson: String): T =
        request("PUT", path, bodyJson).json()

    suspend inline fun <reified T> patch(path: String, bodyJson: String): T =
        request("PATCH", path, bodyJson).json()

    suspend inline fun <reified T> del(path: String, bodyJson: String? = null): T =
        request("DELETE", path, bodyJson).json()

    /** 请求体序列化入口（kotlinx.serialization，字段名与 Go JSON tag 一致）。 */
    inline fun <reified T> encode(value: T): String = Json.encodeToString(value)
}
