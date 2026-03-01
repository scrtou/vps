#!/bin/bash

# =================================================================
#               VPS 高级管理脚本 v2.8.1-FULL (账号/策略分离版)
#
#  新增：
#  - authorized_keys 支持多密钥：追加/替换/查看/清空，自动去重
#  - 从 GitHub 用户名获取公钥：https://github.com/<user>.keys
#
#  继承：
#  - 账号管理与 SSH 认证策略完全分离（策略用 state 文件生成 managed block）
#  - SSH reload/restart 兼容（systemd/service/init.d/HUP），变更自带备份+回滚
#  - iptables 初始化默认保守模式，Docker 出网限制用 DOCKER-USER + 真子网 + 可清理
# =================================================================

# --- 颜色与兼容：若终端不支持，自动禁用颜色 ---
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  BLUE='\033[0;34m'
  NC='\033[0m'
else
  RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi

SSHD_CONFIG="/etc/ssh/sshd_config"
SYSCTL_CONFIG="/etc/sysctl.conf"

# --- 策略状态文件（账号/策略分离） ---
VPSMGR_DIR="/etc/vpsmgr"
SSH_POLICY_STATE="${VPSMGR_DIR}/ssh_policy.state"
SSH_POLICY_BEGIN="# === VPSMGR SSH POLICY BEGIN ==="
SSH_POLICY_END="# === VPSMGR SSH POLICY END ==="

# --- 核心辅助函数 ---
check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}错误：此脚本需要 root 权限运行。请使用 'sudo $0'${NC}"
    exit 1
  fi
}

confirm() {
  read -r -p "$1 [y/N] " response
  case "$response" in
    [yY][eE][sS]|[yY]) return 0 ;;
    *) return 1 ;;
  esac
}

# --- 包管理器检测 ---
detect_pkg_mgr() {
  if command -v apt-get &>/dev/null; then echo "apt"
  elif command -v dnf &>/dev/null; then echo "dnf"
  elif command -v yum &>/dev/null; then echo "yum"
  else echo "none"
  fi
}

check_and_install_sudo() {
  if command -v sudo &> /dev/null; then return 0; fi
  echo -e "${YELLOW}检测到 'sudo' 未安装，正在尝试自动安装...${NC}"

  case "$(detect_pkg_mgr)" in
    apt) apt-get update && apt-get install -y sudo ;;
    dnf) dnf install -y sudo ;;
    yum) yum install -y sudo ;;
    *) echo -e "${RED}错误：无法确定包管理器，请手动安装 sudo。${NC}"; exit 1 ;;
  esac

  command -v sudo &>/dev/null || { echo -e "${RED}错误：sudo 安装失败。${NC}"; exit 1; }
  echo -e "${GREEN}sudo 安装成功。${NC}"
}

# --- fetch 工具（GitHub 拉取 keys 用） ---
check_and_install_fetcher() {
  if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then
    return 0
  fi

  echo -e "${YELLOW}未检测到 curl/wget，正在尝试安装 curl...${NC}"
  case "$(detect_pkg_mgr)" in
    apt)
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y curl
      ;;
    dnf) dnf install -y curl ;;
    yum) yum install -y curl ;;
    *)
      echo -e "${RED}无法识别包管理器，无法自动安装 curl。请手动安装 curl 或 wget。${NC}"
      return 1
      ;;
  esac

  command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1
}

fetch_url() {
  # 用 curl 优先，否则 wget
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url"
  else
    wget -qO- "$url"
  fi
}

# --- 自动安装 iptables/ip6tables ---
check_and_install_iptables() {
  if command -v iptables &>/dev/null; then
    return 0
  fi

  echo -e "${YELLOW}检测到 iptables 未安装，正在尝试自动安装...${NC}"
  case "$(detect_pkg_mgr)" in
    apt)
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y iptables
      ;;
    dnf)
      dnf install -y iptables iptables-services
      systemctl enable --now iptables 2>/dev/null || true
      ;;
    yum)
      yum install -y iptables iptables-services
      systemctl enable --now iptables 2>/dev/null || true
      ;;
    *)
      echo -e "${RED}错误：无法识别包管理器，无法自动安装 iptables。${NC}"
      return 1
      ;;
  esac

  if ! command -v iptables &>/dev/null; then
    echo -e "${RED}错误：iptables 安装失败或不可用。${NC}"
    return 1
  fi

  echo -e "${GREEN}iptables 已可用：$(iptables --version 2>/dev/null | head -n1)${NC}"
  if command -v ip6tables &>/dev/null; then
    echo -e "${GREEN}ip6tables 已可用。${NC}"
  else
    echo -e "${YELLOW}提示：未检测到 ip6tables，将跳过 IPv6 规则。${NC}"
  fi
  return 0
}

# --- 防火墙检测（更稳，不再判断 iptables “inactive”）---
detect_firewall() {
  if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "firewalld"
  elif command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qi "Status: active"; then
    echo "ufw"
  elif command -v iptables &>/dev/null; then
    echo "iptables"
  else
    echo "none"
  fi
}

save_iptables_rules() {
  if ! command -v iptables-save &>/dev/null; then
    echo -e "${YELLOW}提示：未找到 iptables-save，无法保存规则。${NC}"
    return 1
  fi

  if [ -d /etc/iptables ]; then
    iptables-save > /etc/iptables/rules.v4
    command -v ip6tables-save &>/dev/null && ip6tables-save > /etc/iptables/rules.v6 || true
    echo "iptables 规则已保存。"
  elif [ -d /etc/sysconfig ]; then
    iptables-save > /etc/sysconfig/iptables
    command -v ip6tables-save &>/dev/null && ip6tables-save > /etc/sysconfig/ip6tables || true
    echo "iptables 规则已保存。"
  elif command -v apt-get &> /dev/null; then
    echo -e "${YELLOW}为了在重启后保留防火墙规则，建议安装 'iptables-persistent'。${NC}"
    if confirm "是否现在自动安装 'iptables-persistent'？"; then
      apt-get update >/dev/null 2>&1
      DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent >/dev/null 2>&1 || true
      if [ -d /etc/iptables ]; then
        iptables-save > /etc/iptables/rules.v4
        command -v ip6tables-save &>/dev/null && ip6tables-save > /etc/iptables/rules.v6 || true
        echo -e "${GREEN}安装成功，规则已保存。${NC}"
      else
        echo -e "${YELLOW}已尝试安装 iptables-persistent，但未发现 /etc/iptables。请自行确认规则持久化。${NC}"
      fi
    else
      echo -e "${YELLOW}已取消。提示：规则可能不会在重启后保留。${NC}"
    fi
  else
    echo -e "${YELLOW}警告：未找到标准保存路径，规则可能不会在重启后保留。${NC}"
  fi
}

# ================================================================
# ============ SSH 认证策略管理（与账号管理分离） =================
# ================================================================

ensure_vpsmgr_dir() {
  mkdir -p "$VPSMGR_DIR"
  chmod 700 "$VPSMGR_DIR"
}

ssh_service_candidates() { echo "ssh sshd"; }

ssh_reload_or_restart() {
  sshd -t || { echo -e "${RED}错误：sshd 配置检测失败（sshd -t）${NC}"; return 1; }

  echo -e "${GREEN}正在 reload/restart SSH 服务（兼容 systemd/service/init.d/HUP）...${NC}"

  # A) systemd
  if command -v systemctl >/dev/null 2>&1 && systemctl >/dev/null 2>&1; then
    for svc in $(ssh_service_candidates); do
      if systemctl list-unit-files 2>/dev/null | grep -qE "^${svc}\.service"; then
        systemctl reload "$svc" 2>/dev/null && { echo -e "${GREEN}已通过 systemctl reload ${svc}${NC}"; return 0; }
        systemctl restart "$svc" 2>/dev/null && { echo -e "${GREEN}已通过 systemctl restart ${svc}${NC}"; return 0; }
      fi
    done
  fi

  # B) service
  if command -v service >/dev/null 2>&1; then
    for svc in $(ssh_service_candidates); do
      service "$svc" status >/dev/null 2>&1 || continue
      service "$svc" reload  >/dev/null 2>&1 && { echo -e "${GREEN}已通过 service ${svc} reload${NC}"; return 0; }
      service "$svc" restart >/dev/null 2>&1 && { echo -e "${GREEN}已通过 service ${svc} restart${NC}"; return 0; }
    done
  fi

  # C) /etc/init.d
  for svc in $(ssh_service_candidates); do
    [[ -x "/etc/init.d/${svc}" ]] || continue
    "/etc/init.d/${svc}" reload  >/dev/null 2>&1 && { echo -e "${GREEN}已通过 /etc/init.d/${svc} reload${NC}"; return 0; }
    "/etc/init.d/${svc}" restart >/dev/null 2>&1 && { echo -e "${GREEN}已通过 /etc/init.d/${svc} restart${NC}"; return 0; }
  done

  # D) HUP
  local pid
  pid="$(pgrep -xo sshd 2>/dev/null || true)"
  if [[ -n "$pid" ]] && kill -HUP "$pid" >/dev/null 2>&1; then
    echo -e "${GREEN}已对 sshd(${pid}) 发送 HUP（重新加载配置）${NC}"
    return 0
  fi

  echo -e "${RED}错误：无法 reload/restart SSH 服务。${NC}"
  return 1
}

ssh_kbd_opt_name() {
  local out
  out="$(sshd -T 2>/dev/null || true)"
  if echo "$out" | grep -qi '^kbdinteractiveauthentication '; then
    echo "KbdInteractiveAuthentication"
  else
    echo "ChallengeResponseAuthentication"
  fi
}

ssh_backup_config() {
  local backup_file="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
  cp "$SSHD_CONFIG" "$backup_file"
  echo -e "${GREEN}SSH 配置已备份：${backup_file}${NC}"
  echo "$backup_file"
}

policy_state_init() {
  ensure_vpsmgr_dir
  [[ -f "$SSH_POLICY_STATE" ]] || {
    cat >"$SSH_POLICY_STATE" <<EOF
# format:
# GLOBAL_PASSWORD=no|yes   (可选，不写则不改全局默认)
# USER:username:mode[:arg]
# modes:
#   keyonly
#   password
#   sftp_password:/sftp/username
EOF
    chmod 600 "$SSH_POLICY_STATE"
  }
}

policy_state_set_global_password() {
  policy_state_init
  sed -i '/^GLOBAL_PASSWORD=/d' "$SSH_POLICY_STATE"
  case "$1" in
    yes|no) echo "GLOBAL_PASSWORD=$1" >> "$SSH_POLICY_STATE" ;;
    clear) : ;;
    *) echo -e "${RED}无效参数：$1${NC}"; return 1 ;;
  esac
}

policy_state_set_user() {
  policy_state_init
  local u="$1" mode="$2" arg="${3:-}"
  sed -i "\|^USER:${u}:|d" "$SSH_POLICY_STATE"
  if [[ -n "$arg" ]]; then
    echo "USER:${u}:${mode}:${arg}" >> "$SSH_POLICY_STATE"
  else
    echo "USER:${u}:${mode}" >> "$SSH_POLICY_STATE"
  fi
}

policy_state_remove_user() {
  policy_state_init
  local u="$1"
  sed -i "\|^USER:${u}:|d" "$SSH_POLICY_STATE"
}

policy_state_show() {
  policy_state_init
  echo -e "${GREEN}--- 当前策略 state: ${SSH_POLICY_STATE} ---${NC}"
  sed '/^\s*#/d;/^\s*$/d' "$SSH_POLICY_STATE" || true
}

get_user_home() { getent passwd "$1" | awk -F: '{print $6}'; }

# ---------- 多密钥写入：追加/替换/去重 ----------
authorized_keys_path_for_user() {
  local u="$1"
  local home_dir
  home_dir="$(get_user_home "$u")"
  [[ -n "$home_dir" && -d "$home_dir" ]] || return 1
  echo "${home_dir}/.ssh/authorized_keys"
}

ensure_ssh_dir_permissions() {
  local u="$1"
  local home_dir ssh_dir auth_keys
  home_dir="$(get_user_home "$u")" || return 1
  ssh_dir="${home_dir}/.ssh"
  auth_keys="${ssh_dir}/authorized_keys"

  mkdir -p "$ssh_dir"
  chmod 700 "$ssh_dir"
  touch "$auth_keys"
  chmod 600 "$auth_keys"
  chown -R "${u}:${u}" "$ssh_dir"
}

is_valid_pubkey_line() {
  # 允许 ssh-* / sk-* 等，简单校验：至少 2 列，第二列像 base64
  local line="$1"
  line="$(echo "$line" | tr -d '\r')"
  [[ -z "$line" ]] && return 1
  [[ "$line" =~ ^[[:space:]]*# ]] && return 1

  local t b
  t="$(echo "$line" | awk '{print $1}')"
  b="$(echo "$line" | awk '{print $2}')"

  case "$t" in
    ssh-*|sk-*) : ;;
    *) return 1 ;;
  esac

  [[ "$b" =~ ^[A-Za-z0-9+/=]+$ ]] || return 1
  return 0
}

append_keys_to_user() {
  # $1 user, $2 keys_text (multi-line)
  local u="$1" keys_text="$2"
  id "$u" &>/dev/null || { echo -e "${RED}用户不存在：$u${NC}"; return 1; }

  ensure_ssh_dir_permissions "$u" || { echo -e "${RED}无法准备 ~/.ssh 权限${NC}"; return 1; }
  local auth_keys
  auth_keys="$(authorized_keys_path_for_user "$u")" || { echo -e "${RED}无法获取 authorized_keys 路径${NC}"; return 1; }

  local added=0 skipped=0 invalid=0
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if is_valid_pubkey_line "$line"; then
      if grep -qxF "$line" "$auth_keys" 2>/dev/null; then
        skipped=$((skipped+1))
      else
        echo "$line" >> "$auth_keys"
        added=$((added+1))
      fi
    else
      invalid=$((invalid+1))
    fi
  done <<< "$keys_text"

  chown "${u}:${u}" "$auth_keys"
  chmod 600 "$auth_keys"

  echo -e "${GREEN}写入完成：新增 ${added}，已存在跳过 ${skipped}，无效行 ${invalid}${NC}"
  return 0
}

clear_user_authorized_keys() {
  local u="$1"
  id "$u" &>/dev/null || { echo -e "${RED}用户不存在：$u${NC}"; return 1; }
  ensure_ssh_dir_permissions "$u" || return 1
  local auth_keys
  auth_keys="$(authorized_keys_path_for_user "$u")" || return 1
  : > "$auth_keys"
  chown "${u}:${u}" "$auth_keys"
  chmod 600 "$auth_keys"
  echo -e "${GREEN}已清空：$auth_keys${NC}"
}

show_user_authorized_keys() {
  local u="$1"
  id "$u" &>/dev/null || { echo -e "${RED}用户不存在：$u${NC}"; return 1; }
  local auth_keys
  auth_keys="$(authorized_keys_path_for_user "$u")" || { echo -e "${RED}无法获取 authorized_keys 路径${NC}"; return 1; }
  echo -e "${GREEN}--- ${u} 的 authorized_keys：${auth_keys} ---${NC}"
  if [[ -f "$auth_keys" ]]; then
    nl -ba "$auth_keys"
  else
    echo -e "${YELLOW}文件不存在（尚未创建）${NC}"
  fi
}

# 统一导入入口：支持多行粘贴 / 文件 / GitHub
import_pubkeys_interactive() {
  # $1 user, $2 mode: append|replace
  local u="$1" mode="${2:-append}"
  id "$u" &>/dev/null || { echo -e "${RED}用户不存在：$u${NC}"; return 1; }

  if [[ "$mode" == "replace" ]]; then
    echo -e "${YELLOW}将清空该用户现有 authorized_keys 后再导入。${NC}"
    confirm "确认继续？" || return 0
    clear_user_authorized_keys "$u" || return 1
  fi

  echo -e "${BLUE}--- 为用户 ${u} 导入/追加公钥（支持多密钥）---${NC}"
  echo "1) 粘贴公钥（可多行，输入 END 结束）"
  echo "2) 从服务器公钥文件导入（文件可多行）"
  echo "3) 从 GitHub 用户名获取（https://github.com/<user>.keys）"
  echo "4) 查看当前 authorized_keys"
  echo "0) 返回"
  read -r -p "请选择: " c

  case "$c" in
    1)
      echo -e "${YELLOW}请粘贴公钥（可多行），输入 END 结束：${NC}"
      local buf="" line=""
      while IFS= read -r line; do
        [[ "$line" == "END" ]] && break
        buf+="$line"$'\n'
      done
      append_keys_to_user "$u" "$buf"
      ;;
    2)
      read -r -p "请输入公钥文件路径（例如 /root/keys.pub）： " keyfile
      [[ -f "$keyfile" ]] || { echo -e "${RED}文件不存在：$keyfile${NC}"; return 1; }
      append_keys_to_user "$u" "$(cat "$keyfile")"
      ;;
    3)
      check_and_install_fetcher || return 1
      read -r -p "请输入 GitHub 用户名： " gh
      # GitHub 用户名允许字母数字和短横线，不能以短横线开头/结尾（这里做一个保守校验）
      if ! [[ "$gh" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$ ]]; then
        echo -e "${RED}GitHub 用户名格式看起来不合法。${NC}"
        return 1
      fi
      local url keys
      url="https://github.com/${gh}.keys"
      echo -e "${YELLOW}正在拉取：${url}${NC}"
      keys="$(fetch_url "$url" 2>/dev/null || true)"
      if [[ -z "$keys" ]]; then
        echo -e "${YELLOW}未获取到公钥（可能该用户未公开 key / 网络受限 / 用户名不存在）。${NC}"
        return 1
      fi
      append_keys_to_user "$u" "$keys"
      ;;
    4)
      show_user_authorized_keys "$u"
      ;;
    0) return 0 ;;
    *) echo -e "${RED}无效选择${NC}" ;;
  esac
}

manage_user_keys_menu() {
  echo -e "${BLUE}--- 管理用户 authorized_keys（多密钥）---${NC}"
  read -r -p "用户名: " u
  id "$u" &>/dev/null || { echo -e "${RED}用户不存在，请先在【用户管理】创建${NC}"; return 1; }

  while true; do
    echo -e "\n===== authorized_keys 管理：${u} ====="
    echo "1) 追加导入（保留现有）"
    echo "2) 替换导入（清空后重建）"
    echo "3) 查看当前 authorized_keys"
    echo "4) 清空 authorized_keys"
    echo "0) 返回"
    read -r -p "请选择: " k

    case "$k" in
      1) import_pubkeys_interactive "$u" "append" ;;
      2) import_pubkeys_interactive "$u" "replace" ;;
      3) show_user_authorized_keys "$u" ;;
      4) confirm "${YELLOW}确认清空 ${u} 的 authorized_keys？${NC}" && clear_user_authorized_keys "$u" ;;
      0) break ;;
      *) echo -e "${RED}无效选择${NC}" ;;
    esac
  done
}

# ---- SFTP-only + chroot 目录准备（策略侧）----
setup_sftp_chroot_for_user() {
  local u="$1" rootdir="$2"
  id "$u" &>/dev/null || { echo -e "${RED}用户不存在：$u${NC}"; return 1; }

  local upload="${rootdir}/upload"
  mkdir -p "$upload"

  chown root:root "$rootdir"
  chmod 755 "$rootdir"

  chown "${u}:${u}" "$upload"
  chmod 700 "$upload"

  echo -e "${GREEN}已设置 SFTP chroot：${rootdir}（上传目录：${upload}）${NC}"
}

ssh_policy_generate_block() {
  policy_state_init
  local kbd_opt
  kbd_opt="$(ssh_kbd_opt_name)"

  echo "$SSH_POLICY_BEGIN"
  echo "# managed by VPS script (do not edit this block manually)"
  echo "PermitRootLogin no"
  echo "PubkeyAuthentication yes"

  # 可选全局密码策略（不写则保持系统原默认）
  if grep -q '^GLOBAL_PASSWORD=no$' "$SSH_POLICY_STATE"; then
    echo "PasswordAuthentication no"
    echo "${kbd_opt} no"
  elif grep -q '^GLOBAL_PASSWORD=yes$' "$SSH_POLICY_STATE"; then
    echo "PasswordAuthentication yes"
    echo "${kbd_opt} yes"
  fi

  echo ""
  echo "# --- User policies ---"
  grep '^USER:' "$SSH_POLICY_STATE" 2>/dev/null | while IFS=: read -r _ u mode arg; do
    [[ -z "$u" || -z "$mode" ]] && continue
    echo ""
    echo "# user: $u  mode: $mode"
    echo "Match User $u"
    case "$mode" in
      keyonly)
        echo "    AuthenticationMethods publickey"
        echo "    PasswordAuthentication no"
        echo "    ${kbd_opt} no"
        ;;
      password)
        echo "    PasswordAuthentication yes"
        echo "    ${kbd_opt} yes"
        ;;
      sftp_password)
        local chroot="${arg:-/sftp/$u}"
        echo "    PasswordAuthentication yes"
        echo "    ${kbd_opt} yes"
        echo "    ForceCommand internal-sftp"
        echo "    ChrootDirectory ${chroot}"
        echo "    PermitTTY no"
        echo "    X11Forwarding no"
        echo "    AllowTcpForwarding no"
        ;;
      *)
        echo "    # unknown mode: $mode (ignored)"
        ;;
    esac
  done

  echo ""
  echo "$SSH_POLICY_END"
}

ssh_policy_apply() {
  local backup_file tmp
  backup_file="$(ssh_backup_config)"

  sed -i "/^${SSH_POLICY_BEGIN}$/,/^${SSH_POLICY_END}$/d" "$SSHD_CONFIG"

  tmp="$(mktemp)"
  ssh_policy_generate_block > "$tmp"
  cat "$tmp" >> "$SSHD_CONFIG"
  rm -f "$tmp"

  if ! ssh_reload_or_restart; then
    echo -e "${RED}SSH 重载失败，已回滚配置。${NC}"
    cp "$backup_file" "$SSHD_CONFIG"
    ssh_reload_or_restart || true
    return 1
  fi
  echo -e "${GREEN}SSH 策略已应用（managed block 已更新）${NC}"
}

ssh_policy_clear_all() {
  local backup_file
  backup_file="$(ssh_backup_config)"
  sed -i "/^${SSH_POLICY_BEGIN}$/,/^${SSH_POLICY_END}$/d" "$SSHD_CONFIG"
  rm -f "$SSH_POLICY_STATE" 2>/dev/null || true
  if ! ssh_reload_or_restart; then
    echo -e "${RED}清理后 SSH 重载失败，已回滚。${NC}"
    cp "$backup_file" "$SSHD_CONFIG"
    ssh_reload_or_restart || true
    return 1
  fi
  echo -e "${GREEN}已清理所有 VPSMGR SSH 策略（block + state）${NC}"
}

ssh_policy_menu() {
  policy_state_init
  while true; do
    echo -e "\n===== SSH 认证策略管理（与账号管理分离）====="
    echo "1. 应用安全基线：禁 root + 全局禁密码（推荐）"
    echo "2. 全局密码策略：允许/禁止/保持默认"
    echo "3. 设置用户：仅密钥登录（策略）"
    echo "4. 设置用户：允许密码登录（策略）"
    echo "5. 设置用户：SFTP-only + 密码（临时传文件）"
    echo "6. 移除某用户策略"
    echo "7. 管理用户 authorized_keys（多密钥/ GitHub 导入）"
    echo "8. 查看当前策略（state + 当前 managed block）"
    echo "9. 清理全部 SSH 策略（删除 managed block）"
    echo "0. 返回主菜单"
    echo "============================================"
    read -r -p "请选择: " c

    case "$c" in
      1)
        policy_state_set_global_password no
        ssh_policy_apply
        ;;
      2)
        echo "a) 全局允许密码   b) 全局禁止密码   c) 保持系统默认（不设置）"
        read -r -p "请选择(a/b/c): " g
        case "$g" in
          a) policy_state_set_global_password yes ;;
          b) policy_state_set_global_password no ;;
          c) policy_state_set_global_password clear ;;
          *) echo -e "${RED}无效选择${NC}"; continue ;;
        esac
        ssh_policy_apply
        ;;
      3)
        read -r -p "用户名: " u
        id "$u" &>/dev/null || { echo -e "${RED}用户不存在，请先在【用户管理】创建${NC}"; continue; }
        echo -e "${YELLOW}提示：仅密钥登录前，建议先确保该用户已有公钥（可用选项7导入/追加多密钥）。${NC}"
        if confirm "是否现在导入/追加该用户公钥？"; then
          import_pubkeys_interactive "$u" "append" || continue
        fi
        policy_state_set_user "$u" "keyonly"
        ssh_policy_apply
        ;;
      4)
        read -r -p "用户名: " u
        id "$u" &>/dev/null || { echo -e "${RED}用户不存在，请先在【用户管理】创建${NC}"; continue; }
        echo -e "${YELLOW}提示：此项仅允许“SSH 密码认证”，不负责设置系统密码；如需密码请到【用户管理->修改用户密码】${NC}"
        policy_state_set_user "$u" "password"
        ssh_policy_apply
        ;;
      5)
        read -r -p "用户名(建议 tempuser): " u
        id "$u" &>/dev/null || { echo -e "${RED}用户不存在，请先在【用户管理】创建${NC}"; continue; }
        read -r -p "chroot 根目录（默认 /sftp/${u}）: " rootdir
        [[ -z "$rootdir" ]] && rootdir="/sftp/${u}"
        setup_sftp_chroot_for_user "$u" "$rootdir" || continue
        echo -e "${YELLOW}提示：请确保该用户已设置系统密码（用户管理->修改密码），否则无法用密码 SFTP。${NC}"
        policy_state_set_user "$u" "sftp_password" "$rootdir"
        ssh_policy_apply
        ;;
      6)
        read -r -p "用户名: " u
        policy_state_remove_user "$u"
        ssh_policy_apply
        ;;
      7)
        manage_user_keys_menu
        ;;
      8)
        policy_state_show
        echo -e "${GREEN}--- 当前 sshd_config 中的 managed block ---${NC}"
        awk -v b="$SSH_POLICY_BEGIN" -v e="$SSH_POLICY_END" '
          $0==b{p=1}
          p{print}
          $0==e{p=0}
        ' "$SSHD_CONFIG" 2>/dev/null || true
        ;;
      9)
        confirm "${YELLOW}确认清理全部 SSH 策略？${NC}" && ssh_policy_clear_all
        ;;
      0) break ;;
      *) echo -e "${RED}无效选择${NC}" ;;
    esac
  done
}

# ================================================================
# ======================= SSH 配置（端口） ========================
# ================================================================

update_fail2ban_port_if_present() {
  local new_port="$1"
  local jail="/etc/fail2ban/jail.local"
  [[ -f "$jail" ]] || return 0

  if grep -q '^\[sshd\]' "$jail"; then
    if awk 'BEGIN{in=0} /^\[sshd\]/{in=1;next} /^\[/{in=0} {if(in && $0 ~ /^port[[:space:]]*=/){found=1}} END{exit found?0:1}' "$jail"; then
      awk -v p="$new_port" '
        BEGIN{in=0}
        /^\[sshd\]/{in=1; print; next}
        /^\[/{if(in){in=0} print; next}
        {
          if(in && $0 ~ /^port[[:space:]]*=/){print "port     = " p; next}
          print
        }
      ' "$jail" > "${jail}.tmp" && mv "${jail}.tmp" "$jail"
    else
      awk -v p="$new_port" '
        /^\[sshd\]/{print; print "port     = " p; next}
        {print}
      ' "$jail" > "${jail}.tmp" && mv "${jail}.tmp" "$jail"
    fi
  fi
}

change_ssh_port() {
  echo -e "${BLUE}--- 修改 SSH 端口 ---${NC}"
  echo -e "${GREEN}当前 SSH 端口配置：${NC}"
  grep -E "^\s*Port\s+" "$SSHD_CONFIG" || true
  grep -E "^#\s*Port\s+" "$SSHD_CONFIG" | head -n 1 || true

  local old_port
  old_port=$(grep -E "^\s*Port\s+" "$SSHD_CONFIG" | awk '{print $2}' | tail -n1)
  [[ -z "$old_port" ]] && old_port=22

  read -r -p "请输入新的SSH端口号 (1-65535): " new_port
  if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
    echo -e "${RED}错误：无效端口号。${NC}"
    return 1
  fi

  if command -v semanage &>/dev/null; then
    echo -e "${YELLOW}检测到 SELinux，正在添加端口策略...${NC}"
    semanage port -a -t ssh_port_t -p tcp "$new_port" &>/dev/null || true
  fi

  local backup_file
  backup_file="$(ssh_backup_config)"

  sed -i -E '/^\s*#?\s*Port\s+[0-9]+/d' "$SSHD_CONFIG"

  if grep -q "^${SSH_POLICY_BEGIN}$" "$SSHD_CONFIG"; then
    sed -i "/^${SSH_POLICY_BEGIN}$/i Port ${new_port}" "$SSHD_CONFIG"
  else
    echo "Port ${new_port}" >> "$SSHD_CONFIG"
  fi

  echo -e "${YELLOW}正在测试 SSH 配置...${NC}"
  if ! sshd -t; then
    echo -e "${RED}错误：SSH 配置测试失败！已回滚。${NC}"
    cp "$backup_file" "$SSHD_CONFIG"
    return 1
  fi

  local firewall_type
  firewall_type=$(detect_firewall)

  if [[ "$firewall_type" == "iptables" ]] && command -v iptables &>/dev/null; then
    echo "正在为 iptables 添加新端口规则..."
    if iptables -nL VPS-BASELINE >/dev/null 2>&1; then
      iptables -D VPS-BASELINE -p tcp --dport "$old_port" -j ACCEPT 2>/dev/null || true
      iptables -I VPS-BASELINE 1 -p tcp --dport "$new_port" -j ACCEPT 2>/dev/null || iptables -A VPS-BASELINE -p tcp --dport "$new_port" -j ACCEPT
    else
      iptables -I INPUT 1 -p tcp --dport "$new_port" -j ACCEPT 2>/dev/null || true
    fi
    command -v ip6tables &>/dev/null && {
      if ip6tables -nL VPS-BASELINE >/dev/null 2>&1; then
        ip6tables -D VPS-BASELINE -p tcp --dport "$old_port" -j ACCEPT 2>/dev/null || true
        ip6tables -I VPS-BASELINE 1 -p tcp --dport "$new_port" -j ACCEPT 2>/dev/null || ip6tables -A VPS-BASELINE -p tcp --dport "$new_port" -j ACCEPT
      else
        ip6tables -I INPUT 1 -p tcp --dport "$new_port" -j ACCEPT 2>/dev/null || true
      fi
    } || true
    save_iptables_rules || true
  elif [[ "$firewall_type" == "ufw" ]]; then
    ufw allow "${new_port}/tcp" >/dev/null 2>&1 || true
    echo -e "${GREEN}ufw: 已尝试放行 ${new_port}/tcp${NC}"
  elif [[ "$firewall_type" == "firewalld" ]]; then
    firewall-cmd --permanent --add-port="${new_port}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo -e "${GREEN}firewalld: 已尝试放行 ${new_port}/tcp${NC}"
  fi

  echo "正在重载/重启 SSH 服务..."
  if ssh_reload_or_restart; then
    update_fail2ban_port_if_present "$new_port" || true
    systemctl restart fail2ban 2>/dev/null || true
    echo -e "${GREEN}SSH 端口已修改为: $new_port${NC}"
    echo -e "${YELLOW}请使用新端口重新连接！${NC}"
  else
    echo -e "${RED}错误：重载/重启 SSH 服务失败！已回滚配置。${NC}"
    cp "$backup_file" "$SSHD_CONFIG"
    ssh_reload_or_restart || true
    return 1
  fi
}

# ================================================================
# ======================= 用户管理（账号） ========================
# ================================================================

user_management() {
  while true; do
    echo -e "\n===== 用户管理（只管账号，不改 SSH 策略）====="
    echo "1. 新增用户"
    echo "2. 修改用户密码"
    echo "3. 删除用户"
    echo "4. 列出所有用户"
    echo "0. 返回主菜单"
    echo "============================================"
    read -r -p "请选择操作: " user_choice
    case $user_choice in
      1) add_user ;;
      2) change_user_password ;;
      3) delete_user ;;
      4) list_users ;;
      0) break ;;
      *) echo -e "${RED}无效选择${NC}" ;;
    esac
  done
}

add_user() {
  read -r -p "请输入新用户名: " username
  if ! [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    echo -e "${RED}错误：用户名格式不合法。${NC}"
    return 1
  fi
  id "$username" &>/dev/null && { echo -e "${RED}错误：用户已存在${NC}"; return 1; }

  useradd -m -s /bin/bash "$username"
  echo -e "${GREEN}用户 $username 创建成功（仅账号，不含 SSH 策略）${NC}"

  if confirm "是否现在为 $username 设置系统密码（用于本机登录/SSH密码/ sudo）？"; then
    passwd "$username"
  else
    echo -e "${YELLOW}提示：未设置密码。若未来要允许 SSH 密码登录或 SFTP-only+密码，请先设置密码。${NC}"
  fi

  if confirm "是否将用户 $username 添加到 sudo/wheel 组？"; then
    if getent group sudo >/dev/null; then
      usermod -aG sudo "$username"
      echo -e "${GREEN}已加入 sudo 组${NC}"
    elif getent group wheel >/dev/null; then
      usermod -aG wheel "$username"
      echo -e "${GREEN}已加入 wheel 组${NC}"
    else
      echo -e "${YELLOW}警告：未找到 sudo/wheel 组${NC}"
    fi
  fi

  echo -e "${YELLOW}下一步：到主菜单【2. SSH 认证策略管理】设置登录策略，并可在里面导入多密钥/从 GitHub 拉取。${NC}"
}

change_user_password() {
  read -r -p "请输入要修改密码的用户名: " username
  id "$username" &>/dev/null || { echo -e "${RED}错误：用户不存在${NC}"; return 1; }
  passwd "$username"
  echo -e "${GREEN}密码修改成功${NC}"
}

delete_user() {
  read -r -p "请输入要删除的用户名: " username
  id "$username" &>/dev/null || { echo -e "${RED}错误：用户不存在${NC}"; return 1; }

  local uid
  uid=$(id -u "$username")
  if [ "$uid" -lt 1000 ] && [ "$uid" -ne 0 ]; then
    echo -e "${RED}错误：禁止删除 UID<1000 的系统用户。${NC}"
    return 1
  fi
  [ "$username" == "root" ] && { echo -e "${RED}错误：禁止删除 root 用户！${NC}"; return 1; }

  if confirm "${RED}警告：确定删除用户 $username 吗？${NC}"; then
    if confirm "是否同时删除 /home/$username？"; then
      userdel -r "$username"
      echo -e "${GREEN}用户及主目录已删除${NC}"
    else
      userdel "$username"
      echo -e "${GREEN}用户已删除（主目录保留）${NC}"
    fi
    policy_state_remove_user "$username" >/dev/null 2>&1 || true
    ssh_policy_apply >/dev/null 2>&1 || true
  else
    echo "操作已取消。"
  fi
}

list_users() {
  echo -e "${GREEN}--- 系统用户列表（UID >= 1000）---${NC}"
  awk -F: '$3 >= 1000 && $1 != "nobody" {print $1 " (UID: " $3 ")"}' /etc/passwd
}

# ================================================================
# ===================== 防火墙：iptables 初始化 ===================
# ================================================================

enable_iptables() {
  echo -e "${GREEN}正在配置 iptables 基础规则 (IPv4 & IPv6)...${NC}"
  check_and_install_iptables || return 1

  local current_ssh_port
  current_ssh_port=$(grep -E "^\s*Port\s+" "$SSHD_CONFIG" | awk '{print $2}' | tail -n1)
  [ -z "$current_ssh_port" ] && current_ssh_port=22

  local docker_present="no"
  if command -v docker &>/dev/null; then
    iptables -S 2>/dev/null | grep -qE '^-N DOCKER\b' && docker_present="yes"
  fi

  echo -e "${YELLOW}请选择 iptables 初始化模式：${NC}"
  echo "1) 保守模式（推荐）：不清空现有规则，只维护 VPS-BASELINE 链并插入 jump"
  echo "2) 强制重置：清空并重置 filter 规则（可能影响业务；Docker 存在时不建议）"
  read -r -p "请选择(1/2，默认1): " mode
  [ -z "$mode" ] && mode="1"

  if [[ "$docker_present" == "yes" && "$mode" == "2" ]]; then
    echo -e "${YELLOW}检测到 Docker：强制重置可能破坏容器网络。已自动降级为保守模式。${NC}"
    mode="1"
  fi

  if [[ "$mode" == "1" ]]; then
    local chain="VPS-BASELINE"
    iptables -N "$chain" 2>/dev/null || true
    iptables -F "$chain" 2>/dev/null || true

    iptables -C INPUT -j "$chain" 2>/dev/null || iptables -I INPUT 1 -j "$chain"

    iptables -A "$chain" -i lo -j ACCEPT
    iptables -A "$chain" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A "$chain" -p tcp --dport "$current_ssh_port" -j ACCEPT
    iptables -A "$chain" -p tcp --dport 80 -j ACCEPT
    iptables -A "$chain" -p tcp --dport 443 -j ACCEPT
    iptables -A "$chain" -p icmp --icmp-type echo-request -j ACCEPT
    iptables -A "$chain" -j RETURN

    if command -v ip6tables &>/dev/null; then
      local chain6="VPS-BASELINE"
      ip6tables -N "$chain6" 2>/dev/null || true
      ip6tables -F "$chain6" 2>/dev/null || true
      ip6tables -C INPUT -j "$chain6" 2>/dev/null || ip6tables -I INPUT 1 -j "$chain6"

      ip6tables -A "$chain6" -i lo -j ACCEPT
      ip6tables -A "$chain6" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      ip6tables -A "$chain6" -p tcp --dport "$current_ssh_port" -j ACCEPT
      ip6tables -A "$chain6" -p tcp --dport 80 -j ACCEPT
      ip6tables -A "$chain6" -p tcp --dport 443 -j ACCEPT
      ip6tables -A "$chain6" -p ipv6-icmp -j ACCEPT
      ip6tables -A "$chain6" -j RETURN
    fi

    echo -e "${YELLOW}是否把 INPUT 默认策略设为 DROP（更安全但可能影响未放行业务）？${NC}"
    if confirm "确认设置 INPUT=DROP？"; then
      iptables -P INPUT DROP
      iptables -P OUTPUT ACCEPT
      if [[ "$docker_present" == "yes" ]]; then
        echo -e "${YELLOW}检测到 Docker：保持 FORWARD 策略不改（避免容器网络异常）${NC}"
      else
        iptables -P FORWARD DROP
      fi

      if command -v ip6tables &>/dev/null; then
        ip6tables -P INPUT DROP
        ip6tables -P OUTPUT ACCEPT
        if [[ "$docker_present" != "yes" ]]; then
          ip6tables -P FORWARD DROP
        fi
      fi
    else
      echo -e "${YELLOW}保守模式：未改变默认策略（仅插入允许链）。${NC}"
    fi

    save_iptables_rules || true
    echo -e "${GREEN}iptables 保守初始化完成：开放 SSH($current_ssh_port), 80, 443, ICMP；尽量不破坏现有规则${NC}"
    return 0
  fi

  echo -e "${YELLOW}强制重置将清空现有 filter 规则。${NC}"
  confirm "确定继续？" || { echo "已取消。"; return 0; }

  iptables -F && iptables -X && iptables -Z || { echo -e "${RED}iptables 初始化失败${NC}"; return 1; }
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -p tcp --dport "$current_ssh_port" -j ACCEPT
  iptables -A INPUT -p tcp --dport 80 -j ACCEPT
  iptables -A INPUT -p tcp --dport 443 -j ACCEPT
  iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

  if command -v ip6tables &>/dev/null; then
    ip6tables -F && ip6tables -X && ip6tables -Z || { echo -e "${YELLOW}ip6tables 初始化失败，跳过 IPv6 规则${NC}"; }
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT ACCEPT
    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
    ip6tables -A INPUT -p tcp --dport "$current_ssh_port" -j ACCEPT
    ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT
    ip6tables -A INPUT -p tcp --dport 443 -j ACCEPT
  fi

  save_iptables_rules || true
  echo -e "${GREEN}iptables 已强制重置，默认开放：SSH($current_ssh_port), 80, 443, ICMP${NC}"
}

configure_ports() {
  local firewall
  firewall=$(detect_firewall)
  if [[ "$firewall" == "none" ]]; then
    echo -e "${RED}错误：未检测到可用防火墙（iptables/ufw/firewalld）。${NC}"
    return 1
  fi

  echo "===== 配置防火墙端口 (当前: $firewall) ====="
  echo "1. 开放端口"
  echo "2. 关闭端口"
  read -r -p "请选择操作: " action
  read -r -p "请输入端口号: " port
  if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo -e "${RED}错误：无效端口号${NC}"
    return 1
  fi
  read -r -p "选择协议 (tcp/udp/both): " protocol
  if [[ "$protocol" != "tcp" && "$protocol" != "udp" && "$protocol" != "both" ]]; then
    echo -e "${RED}错误：无效协议${NC}"
    return 1
  fi

  if [[ "$firewall" == "iptables" ]]; then
    local rule_action="-A" op_text="开放"
    [ "$action" == "2" ] && rule_action="-D" && op_text="关闭"

    if [[ "$protocol" == "tcp" || "$protocol" == "both" ]]; then
      iptables "$rule_action" INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
      command -v ip6tables &>/dev/null && ip6tables "$rule_action" INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
      echo -e "${GREEN}iptables: 已${op_text} TCP 端口 $port${NC}"
    fi
    if [[ "$protocol" == "udp" || "$protocol" == "both" ]]; then
      iptables "$rule_action" INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
      command -v ip6tables &>/dev/null && ip6tables "$rule_action" INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
      echo -e "${GREEN}iptables: 已${op_text} UDP 端口 $port${NC}"
    fi
    save_iptables_rules || true

  elif [[ "$firewall" == "ufw" ]]; then
    local proto_list=()
    [[ "$protocol" == "tcp" || "$protocol" == "both" ]] && proto_list+=("tcp")
    [[ "$protocol" == "udp" || "$protocol" == "both" ]] && proto_list+=("udp")

    for p in "${proto_list[@]}"; do
      if [[ "$action" == "1" ]]; then
        ufw allow "${port}/${p}" >/dev/null 2>&1 || true
        echo -e "${GREEN}ufw: 已开放 ${port}/${p}${NC}"
      else
        ufw delete allow "${port}/${p}" >/dev/null 2>&1 || true
        echo -e "${GREEN}ufw: 已关闭 ${port}/${p}${NC}"
      fi
    done

  elif [[ "$firewall" == "firewalld" ]]; then
    local op="--add-port" op_text="开放"
    [[ "$action" == "2" ]] && op="--remove-port" && op_text="关闭"
    if [[ "$protocol" == "tcp" || "$protocol" == "both" ]]; then
      firewall-cmd --permanent "$op=${port}/tcp" >/dev/null 2>&1 || true
      echo -e "${GREEN}firewalld: 已${op_text} ${port}/tcp${NC}"
    fi
    if [[ "$protocol" == "udp" || "$protocol" == "both" ]]; then
      firewall-cmd --permanent "$op=${port}/udp" >/dev/null 2>&1 || true
      echo -e "${GREEN}firewalld: 已${op_text} ${port}/udp${NC}"
    fi
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

show_firewall_rules() {
  local firewall
  firewall=$(detect_firewall)
  echo -e "${GREEN}--- 当前防火墙规则 ($firewall) ---${NC}"
  case "$firewall" in
    firewalld) firewall-cmd --list-all ;;
    ufw) ufw status verbose ;;
    iptables)
      echo -e "${BLUE}--- IPv4 (iptables) ---${NC}"
      iptables -L -n -v --line-numbers
      if command -v ip6tables &>/dev/null; then
        echo -e "\n${BLUE}--- IPv6 (ip6tables) ---${NC}"
        ip6tables -L -n -v --line-numbers
      else
        echo -e "\n${YELLOW}未安装 ip6tables，IPv6 规则未显示。${NC}"
      fi
      ;;
    *) echo "没有活动的防火墙服务。" ;;
  esac
}

# ================================================================
# ======================= 端口转发管理（iptables）=================
# ================================================================

port_forwarding_menu() {
  if [[ "$(detect_firewall)" != "iptables" ]]; then
    echo -e "${RED}错误：端口转发功能目前仅支持 iptables。${NC}"
    return
  fi
  while true; do
    echo -e "\n===== 端口转发管理 (仅IPv4) ====="
    echo "1. 添加端口转发"
    echo "2. 删除端口转发"
    echo "3. 查看当前转发规则"
    echo "0. 返回主菜单"
    echo "=============================="
    read -r -p "请选择操作: " choice
    case $choice in
      1) add_port_forwarding ;;
      2) delete_port_forwarding ;;
      3) view_port_forwarding ;;
      0) break ;;
      *) echo -e "${RED}无效选择${NC}" ;;
    esac
  done
}

enable_ip_forwarding() {
  if ! grep -q -E "^\s*net.ipv4.ip_forward\s*=\s*1" "$SYSCTL_CONFIG"; then
    sed -i '/^\s*#\?\s*net.ipv4.ip_forward/d' "$SYSCTL_CONFIG"
    echo "net.ipv4.ip_forward=1" >> "$SYSCTL_CONFIG"
  fi
  sysctl -p "$SYSCTL_CONFIG" >/dev/null 2>&1 || true
}

add_port_forwarding() {
  echo -e "${BLUE}--- 添加端口转发 ---${NC}"
  read -r -p "协议 (tcp/udp): " proto
  [[ "$proto" != "tcp" && "$proto" != "udp" ]] && { echo -e "${RED}无效协议${NC}"; return 1; }

  read -r -p "源端口: " sport
  ! [[ "$sport" =~ ^[0-9]+$ ]] && { echo -e "${RED}无效源端口${NC}"; return 1; }

  read -r -p "目标IP(空=127.0.0.1): " daddr
  [ -z "$daddr" ] && daddr="127.0.0.1"

  read -r -p "目标端口: " dport
  ! [[ "$dport" =~ ^[0-9]+$ ]] && { echo -e "${RED}无效目标端口${NC}"; return 1; }

  enable_ip_forwarding

  iptables -t nat -A PREROUTING -p "$proto" --dport "$sport" -j DNAT --to-destination "${daddr}:${dport}" || return 1
  if [[ "$daddr" != "127.0.0.1" ]]; then
    iptables -A FORWARD -p "$proto" -d "$daddr" --dport "$dport" -j ACCEPT || return 1
  fi
  iptables -t nat -A POSTROUTING -p "$proto" -d "$daddr" --dport "$dport" -j MASQUERADE || return 1

  save_iptables_rules || true
  echo -e "${GREEN}已添加转发：$sport -> $daddr:$dport${NC}"
}

delete_port_forwarding() {
  echo -e "${BLUE}--- 删除端口转发 ---${NC}"
  read -r -p "协议 (tcp/udp): " proto
  read -r -p "源端口: " sport
  read -r -p "目标IP(空=127.0.0.1): " daddr
  [ -z "$daddr" ] && daddr="127.0.0.1"
  read -r -p "目标端口: " dport

  iptables -t nat -D PREROUTING -p "$proto" --dport "$sport" -j DNAT --to-destination "${daddr}:${dport}" 2>/dev/null || true
  [[ "$daddr" != "127.0.0.1" ]] && iptables -D FORWARD -p "$proto" -d "$daddr" --dport "$dport" -j ACCEPT 2>/dev/null || true
  iptables -t nat -D POSTROUTING -p "$proto" -d "$daddr" --dport "$dport" -j MASQUERADE 2>/dev/null || true

  save_iptables_rules || true
  echo -e "${GREEN}已尝试删除转发：$sport -> $daddr:$dport${NC}"
}

view_port_forwarding() {
  echo -e "${BLUE}--- 当前 NAT PREROUTING 规则 ---${NC}"
  iptables -t nat -L PREROUTING -n -v --line-numbers
}

# ================================================================
# ===================== Fail2Ban 自动安装/启用 =====================
# ================================================================

fail2ban_backend_detect() {
  if command -v systemctl >/dev/null 2>&1 && command -v journalctl >/dev/null 2>&1; then
    echo "systemd"
  else
    echo "auto"
  fi
}

install_fail2ban() {
  echo -e "${BLUE}--- 安装并启用 Fail2Ban ---${NC}"
  case "$(detect_pkg_mgr)" in
    apt)
      apt-get update >/dev/null 2>&1
      DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban >/dev/null 2>&1
      ;;
    dnf) dnf install -y fail2ban ;;
    yum) yum install -y fail2ban ;;
    *)
      echo -e "${RED}无法识别包管理器，Fail2Ban 安装失败。${NC}"
      return 1
      ;;
  esac

  local ssh_port
  ssh_port=$(grep -E "^\s*Port\s+" "$SSHD_CONFIG" | awk '{print $2}' | tail -n1)
  [ -z "$ssh_port" ] && ssh_port=22

  local backend
  backend="$(fail2ban_backend_detect)"

  cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = ${backend}
ignoreip = 127.0.0.1/8

[sshd]
enabled  = true
port     = ${ssh_port}
EOF

  systemctl enable fail2ban --now >/dev/null 2>&1 || true
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    echo -e "${GREEN}Fail2Ban 已运行（sshd 端口：${ssh_port}，backend：${backend}）${NC}"
  else
    echo -e "${YELLOW}Fail2Ban 可能未运行（非 systemd 环境下属正常）。可尝试：service fail2ban restart${NC}"
  fi
}

# ================================================================
# ===== Docker 容器出网安全等级（iptables / DOCKER-USER）==========
# ================================================================

ensure_docker_user_chain() {
  iptables -nL DOCKER-USER >/dev/null 2>&1 || iptables -N DOCKER-USER
  iptables -C DOCKER-USER -j RETURN >/dev/null 2>&1 || iptables -A DOCKER-USER -j RETURN
}

get_docker_subnets() {
  command -v docker >/dev/null 2>&1 || return 0
  docker network ls -q 2>/dev/null | while read -r nid; do
    docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' "$nid" 2>/dev/null
  done | awk 'NF' | sort -u
}

docker_egress_clear_managed_rules() {
  local rules
  rules="$(iptables -S DOCKER-USER 2>/dev/null | grep 'VPSMGR_DOCKER_EGRESS' || true)"
  if [[ -z "$rules" ]]; then
    echo -e "${YELLOW}未发现可清理的 VPSMGR Docker 出网规则。${NC}"
    return 0
  fi

  echo "$rules" | sed 's/^-A /-D /' | while read -r line; do
    # shellcheck disable=SC2086
    iptables $line 2>/dev/null || true
  done
  echo -e "${GREEN}已清理 VPSMGR_DOCKER_EGRESS 规则（DOCKER-USER）。${NC}"
}

docker_security_menu() {
  echo -e "${BLUE}--- Docker 容器出网安全等级（iptables / DOCKER-USER）---${NC}"
  check_and_install_iptables || return 1
  command -v docker >/dev/null 2>&1 || { echo -e "${RED}未检测到 docker 命令，取消。${NC}"; return 1; }

  ensure_docker_user_chain

  local subnets
  subnets="$(get_docker_subnets)"
  if [[ -z "$subnets" ]]; then
    echo -e "${YELLOW}未检测到 Docker 子网（docker network inspect 无输出）。仍可按“自定义子网”配置。${NC}"
  else
    echo -e "${GREEN}检测到 Docker 子网：${NC}"
    echo "$subnets" | sed 's/^/  - /'
  fi

  echo -e "${YELLOW}说明：在 DOCKER-USER 链限制容器发起 NEW 连接的出网行为，较不易被 Docker 规则重排影响。${NC}"
  echo "1. 仅允许 80/443 出网（推荐）"
  echo "2. 完全禁止容器发起 NEW 出网（最严格）"
  echo "3. 仅对指定子网生效（最灵活）"
  echo "4. 查看当前 DOCKER-USER 规则"
  echo "5. 清理本脚本添加的 Docker 出网规则"
  echo "0. 返回"
  read -r -p "请选择: " c

  case "$c" in
    1)
      docker_egress_clear_managed_rules
      if [[ -n "$subnets" ]]; then
        while read -r net; do
          [[ -z "$net" ]] && continue
          iptables -I DOCKER-USER 1 -s "$net" -p tcp -m conntrack --ctstate NEW -m multiport --dports 80,443 \
            -m comment --comment VPSMGR_DOCKER_EGRESS -j ACCEPT
          iptables -I DOCKER-USER 2 -s "$net" -m conntrack --ctstate NEW \
            -m comment --comment VPSMGR_DOCKER_EGRESS -j DROP
        done <<< "$subnets"
        echo -e "${GREEN}已设置：所有 Docker 子网仅允许 80/443 发起 NEW 出网，其它 NEW 丢弃（DOCKER-USER）。${NC}"
      else
        echo -e "${YELLOW}未检测到子网，请用选项 3 自定义子网。${NC}"
      fi
      save_iptables_rules || true
      ;;
    2)
      docker_egress_clear_managed_rules
      if [[ -n "$subnets" ]]; then
        while read -r net; do
          [[ -z "$net" ]] && continue
          iptables -I DOCKER-USER 1 -s "$net" -m conntrack --ctstate NEW \
            -m comment --comment VPSMGR_DOCKER_EGRESS -j DROP
        done <<< "$subnets"
        echo -e "${GREEN}已设置：所有 Docker 子网禁止发起 NEW 出网（DOCKER-USER）。${NC}"
      else
        echo -e "${YELLOW}未检测到子网，请用选项 3 自定义子网。${NC}"
      fi
      save_iptables_rules || true
      ;;
    3)
      read -r -p "输入要限制/放行的子网（例如 172.30.0.0/16）： " net
      [ -z "$net" ] && { echo -e "${RED}未输入子网，取消。${NC}"; return 1; }

      echo "对该子网应用："
      echo "  a) 仅允许 80/443 NEW 出网"
      echo "  b) 禁止 NEW 出网"
      read -r -p "请选择(a/b): " m

      docker_egress_clear_managed_rules

      if [[ "$m" == "a" ]]; then
        iptables -I DOCKER-USER 1 -s "$net" -p tcp -m conntrack --ctstate NEW -m multiport --dports 80,443 \
          -m comment --comment VPSMGR_DOCKER_EGRESS -j ACCEPT
        iptables -I DOCKER-USER 2 -s "$net" -m conntrack --ctstate NEW \
          -m comment --comment VPSMGR_DOCKER_EGRESS -j DROP
        echo -e "${GREEN}已设置：$net 仅允许 80/443 发起 NEW 出网，其它 NEW 丢弃。${NC}"
      elif [[ "$m" == "b" ]]; then
        iptables -I DOCKER-USER 1 -s "$net" -m conntrack --ctstate NEW \
          -m comment --comment VPSMGR_DOCKER_EGRESS -j DROP
        echo -e "${GREEN}已设置：$net 禁止发起 NEW 出网。${NC}"
      else
        echo -e "${RED}无效选择${NC}"
        return 1
      fi

      save_iptables_rules || true
      ;;
    4)
      iptables -L DOCKER-USER -n -v --line-numbers
      ;;
    5)
      docker_egress_clear_managed_rules
      save_iptables_rules || true
      ;;
    0) return ;;
    *) echo -e "${RED}无效选择${NC}" ;;
  esac
}

# ================================================================
# ======================= Caddy 规则片段生成 ======================
# ================================================================

install_caddy_security() {
  echo -e "${BLUE}--- 生成 Caddy 防扫描规则片段 ---${NC}"
  mkdir -p /etc/caddy/snippets

  cat >/etc/caddy/snippets/security.caddy <<'EOF'
(common_security) {
    @bad_ua {
        header_regexp User-Agent (?i)(nmap|masscan|zgrab|sqlmap|nikto|gobuster|dirbuster|curl|wget|python|go-http-client)
    }
    respond @bad_ua 403

    @bad_path {
        path_regexp bad (
            \.env|
            \.git|
            wp-admin|
            wp-login|
            phpMyAdmin|
            adminer|
            \.sql|
            \.bak|
            \.zip
        )
    }
    respond @bad_path 403
}

# 注意：rate_limit 指令通常需要对应 Caddy 模块支持；
# 如果你的 Caddy 未包含该模块，请不要 import 下面 (rate_limit) 或自行删除它。
(rate_limit) {
    rate_limit {
        zone global
        key {remote_host}
        events 30
        window 10s
    }
}
EOF

  echo -e "${GREEN}已写入：/etc/caddy/snippets/security.caddy${NC}"
  echo -e "${YELLOW}在站点块中使用：${NC}"
  echo -e "${YELLOW}  import /etc/caddy/snippets/security.caddy${NC}"
  echo -e "${YELLOW}  import common_security${NC}"
  echo -e "${YELLOW}  # import rate_limit  (若模块不支持请勿启用)${NC}"
}

# ================================================================
# ======================= sysctl 网络加固（幂等）===================
# ================================================================

harden_sysctl() {
  echo -e "${BLUE}--- sysctl 网络安全加固 ---${NC}"
  local marker_begin="# ---- v2.8.1 security hardening BEGIN ----"
  local marker_end="# ---- v2.8.1 security hardening END ----"

  if grep -qF "$marker_begin" "$SYSCTL_CONFIG"; then
    sed -i "/$marker_begin/,/$marker_end/d" "$SYSCTL_CONFIG"
  fi

  cat >>"$SYSCTL_CONFIG" <<EOF

$marker_begin
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
$marker_end
EOF

  sysctl -p "$SYSCTL_CONFIG" >/dev/null 2>&1 || true
  echo -e "${GREEN}sysctl 加固已应用。${NC}"
}

# ================================================================
# ======================= 快速恶意进程检查 ========================
# ================================================================

quick_malware_check() {
  echo -e "${BLUE}--- 快速恶意进程检查 ---${NC}"
  local out
  out=$(ps aux | egrep -i "scanner|masscan|nmap|zmap|check -f|\.\/scanner|\.\/check|socks5|pass\.txt|ok\.list" | grep -v grep || true)
  if [[ -n "$out" ]]; then
    echo -e "${RED}发现可疑进程（仅供线索，建议进一步排查）：${NC}"
    echo "$out"
  else
    echo -e "${GREEN}未发现明显恶意进程特征。${NC}"
  fi
}

# ================================================================
# ======================= 一键安全初始化 ==========================
# ================================================================

security_init_full() {
  echo -e "${BLUE}=== 一键安全初始化（v2.8.1-FULL）===${NC}"
  echo -e "${YELLOW}将执行：SSH 安全基线（禁root+全局禁密码） + Fail2Ban + sysctl 加固 + Docker 出网策略 + 生成 Caddy 防扫描规则${NC}"
  confirm "确认继续？" || { echo "操作已取消。"; return; }

  policy_state_set_global_password no
  ssh_policy_apply || return 1

  install_fail2ban || return 1
  harden_sysctl || true
  docker_security_menu || true
  install_caddy_security || true

  echo -e "${GREEN}一键安全初始化完成。${NC}"
}

# ================================================================
# ============================= 主程序 ============================
# ================================================================

main() {
  check_root
  check_and_install_sudo
  policy_state_init

  while true; do
    local firewall_type
    firewall_type=$(detect_firewall)

    clear
    echo "========================================="
    echo "   VPS 高级管理脚本 v2.8.1-FULL (分离版)  "
    echo "========================================="
    echo " 1. 用户管理（账号：新增/删/改密码/sudo）"
    echo " 2. SSH 认证策略管理（仅密钥/密码/SFTP-only）"
    echo " 3. 修改 SSH 端口"
    echo "-----------------------------------------"
    echo " 4. 启用并初始化 iptables 防火墙（保守/强制）"
    echo " 5. 配置防火墙端口 (当前: $firewall_type)"
    echo " 6. 查看当前防火墙规则 (当前: $firewall_type)"
    echo " 7. 端口转发管理 (iptables)"
    echo "-----------------------------------------"
    echo " 8. 安装并启用 Fail2Ban"
    echo " 9. Docker 容器出网安全等级（DOCKER-USER / iptables）"
    echo "10. 生成 Caddy 防扫描规则片段"
    echo "11. sysctl 网络安全加固"
    echo "12. 快速恶意进程检查"
    echo "13. 一键安全初始化（推荐）"
    echo " 0. 退出"
    echo "========================================="
    read -r -p "请选择功能: " choice

    case $choice in
      1) user_management ;;
      2) ssh_policy_menu ;;
      3) change_ssh_port ;;
      4)
        if confirm "${YELLOW}将配置 iptables（默认保守模式，不清空现有规则）。继续吗？${NC}"; then
          enable_iptables
        else
          echo "操作已取消。"
        fi
        ;;
      5) configure_ports ;;
      6) show_firewall_rules ;;
      7) port_forwarding_menu ;;
      8) install_fail2ban ;;
      9) docker_security_menu ;;
      10) install_caddy_security ;;
      11) harden_sysctl ;;
      12) quick_malware_check ;;
      13) security_init_full ;;
      0) echo "退出脚本"; exit 0 ;;
      *) echo -e "${RED}无效的选择，请重试${NC}" ;;
    esac

    read -r -p $'\n按Enter键返回主菜单...'
  done
}

main
