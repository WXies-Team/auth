import Alpine from 'alpinejs';
import { createIcons, Lock, ShieldCheck, KeyRound, Check, Monitor, Settings, ChevronRight, Users, FolderOpen, ScrollText, User, LogOut } from 'lucide';
import './passkey-login';

window.Alpine = Alpine;
Alpine.start();

// Lucide：只替换静态 HTML 里的图标占位（服务端渲染的部分）
createIcons({ icons: { Lock, ShieldCheck, KeyRound, Check, Monitor, Settings, ChevronRight, Users, FolderOpen, ScrollText, User, LogOut } });
