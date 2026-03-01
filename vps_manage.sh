#!/bin/bash
# =================================================================
# VPS 高级管理脚本 v3.1.2-TOOLBOX-FINAL
#
# ✅ 保持 v2.7/v2.8 的“完整工具箱”功能 + 已修复/增强：
# - 账号管理 与 SSH 认证策略 完全分离（state -> /etc/ssh/sshd_config.d/99-vpsmgr.conf）
# - 禁止 root SSH 登录（包括密钥），并清理 sshd_config 中所有非注释 PermitRootLogin 防止混乱
# - authorized_keys 多密钥：追加/替换/查看/清空，自动去重
# - GitHub 用户名拉取公钥：https://github.com/<user>.keys
# - SSH reload/restart 兼容（systemd/service/init.d）
# - 读取“生效 SSH 配置”用 sshd -T -f /etc/ssh/sshd_config（包含 include）
# - 自动修复云镜像缺失 sudoers 组授权（%sudo / %wheel）
#
# - iptables 自动安装 + 规则保存（含 iptables-persistent 提示）
# - iptables 初始化：保守模式（VPS-BASELINE 链）/ 强制重置（无 Docker）
# - 端口开放/关闭（iptables/ufw/firewalld）
# - 查看防火墙规则
# - 端口转发管理（iptables NAT）
# - Fail2Ban 自动安装启用 + 自动读取 SSH 端口（修复 awk in 关键字问题）
# - Docker 容器出网控制：DOCKER-USER + 自动识别 Docker 子网 + 可清理
# - Caddy 防扫描 snippet 生成
# - sysctl 网络加固（幂等写入）
# - 快速恶意进程检查
# - 一键安全初始化（推荐组合）
#
# v3.1.2 新增：
# - ✅ 用户管理：现有用户“移入/移除 sudo(wheel) 组”、查看组成员/授权状态
# =================================================================

set -uo pipefail

# --- 颜色与兼容：若终端不支持，自动禁用颜色 ---
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONF_DIR="/etc/ssh/sshd_config.d"
SSHD_VPSMGR_CONF="${SSHD_CONF_DIR}/99-vpsmgr.conf"
SYSCTL_CONFIG="/etc/sysctl.conf"

VPSMGR_DIR="/etc/vpsmgr"
SSH_POLICY_STATE="${VPSMGR_DIR}/ssh_policy.state"

# 兼容旧版本 block（自动清理）
OLD_POLICY_BEGIN="# === VPSMGR SSH POLICY BEGIN ==="
OLD_POLICY_END="# === VPSMGR SSH POLICY END ==="
OLD_GLOBAL_BEGIN="# === VPSMGR SSH GLOBAL BEGIN ==="
OLD_GLOBAL_END="# === VPSMGR SSH GLOBAL END ==="
OLD_USER_BEGIN="# === VPSMGR SSH USERPOLICY BEGIN ==="
OLD_USER_END="# === VPSMGR SSH USERPOLICY END ==="

# ------------------ 基础函数 ------------------
die(){ echo -e "${RED}ERROR: $*${NC}" >&2; exit 1; }
info(){ echo -e "${GREEN}==> $*${NC}"; }
warn(){ echo -e "${YELLOW}==> $*${NC}"; }

check_root() {
  [[ ${EUID} -eq 0 ]] || die "此脚本需要 root 权限运行。请使用 sudo 运行。"
}

confirm() {
  read -r -p "$1 [y/N] " response
  case "$response" in
    [yY][eE][sS]|[yY]) return 0 ;;
    *) return 1 ;;
  esac
}

detect_pkg_mgr() {
  if command -v apt-get &>/dev/null; then echo "apt"
  elif command -v dnf &>/dev/null; then echo "dnf"
  elif command -v yum &>/dev/null; then echo "yum"
  else echo "none"
  fi
}

ensure_vpsmgr_dir() {
  mkdir -p "$VPSMGR_DIR"
  chmod 700 "$VPSMGR_DIR"
}

# ------------------ sudo / sudoers 修复 ------------------
check_and_install_sudo() {
  command -v sudo &>/dev/null && return 0
  warn "检测到 sudo 未安装，正在安装..."
  case "$(detect_pkg_mgr)" in
    apt) apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y sudo ;;
    dnf) dnf install -y sudo ;;
    yum) yum install -y sudo ;;
    *) die "无法识别包管理器，请手动安装 sudo" ;;
  esac
  command -v sudo &>/dev/null || die "sudo 安装失败"
}

ensure_sudo_group_rule() {
  # 自动确保 sudoers 授权 sudo 或 wheel 组（云镜像常缺）
  local has_sudo_rule has_wheel_rule
  has_sudo_rule="$(grep -RIs --no-messages '^[[:space:]]*%sudo[[:space:]]' /etc/sudoers /etc/sudoers.d 2>/dev/null || true)"
  has_wheel_rule="$(grep -RIs --no-messages '^[[:space:]]*%wheel[[:space:]]' /etc/sudoers /etc/sudoers.d 2>/dev/null || true)"

  if getent group sudo >/dev/null 2>&1 && [[ -z "$has_sudo_rule" ]]; then
    cat >/etc/sudoers.d/90-vpsmgr-sudo-group <<'EOF'
%sudo ALL=(ALL:ALL) ALL
EOF
    chmod 0440 /etc/sudoers.d/90-vpsmgr-sudo-group
    visudo -cf /etc/sudoers >/dev/null 2>&1 || {
      rm -f /etc/sudoers.d/90-vpsmgr-sudo-group
      die "sudoers 语法校验失败，已撤销 90-vpsmgr-sudo-group"
    }
    info "已补齐 sudoers：%sudo ALL=(ALL:ALL) ALL"
  fi

  if getent group wheel >/dev/null 2>&1 && [[ -z "$has_wheel_rule" ]]; then
    cat >/etc/sudoers.d/90-vpsmgr-wheel-group <<'EOF'
%wheel ALL=(ALL) ALL
EOF
    chmod 0440 /etc/sudoers.d/90-vpsmgr-wheel-group
    visudo -cf /etc/sudoers >/dev/null 2>&1 || {
      rm -f /etc/sudoers.d/90-vpsmgr-wheel-group
      die "sudoers 语法校验失败，已撤销 90-vpsmgr-wheel-group"
    }
    info "已补齐 sudoers：%wheel ALL=(ALL) ALL"
  fi
}

# ===== 新增：sudo/wheel 组管理 =====
detect_admin_group() {
  # 优先 sudo，其次 wheel
  if getent group sudo >/dev/null 2>&1; then
    echo "sudo"
  elif getent group wheel >/dev/null 2>&1; then
    echo "wheel"
  else
    echo ""
  fi
}

add_user_to_admin_group() {
  local u="$1"
  id "$u" &>/dev/null || { warn "用户不存在：$u"; return 1; }

  local g
  g="$(detect_admin_group)"
  [[ -n "$g" ]] || { warn "系统未找到 sudo/wheel 组"; return 1; }

  ensure_sudo_group_rule || true
  if id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -qx "$g"; then
    warn "用户 $u 已在 $g 组中"
    return 0
  fi

  usermod -aG "$g" "$u" || { warn "添加到 $g 组失败"; return 1; }
  info "已将用户 $u 加入 $g 组"
  warn "提示：用户加入组后需要退出并重新登录一次才能在会话中生效。"
}

remove_user_from_admin_group() {
  local u="$1"
  id "$u" &>/dev/null || { warn "用户不存在：$u"; return 1; }

  local g
  g="$(detect_admin_group)"
  [[ -n "$g" ]] || { warn "系统未找到 sudo/wheel 组"; return 1; }

  # 优先 gpasswd/deluser
  if command -v gpasswd >/dev/null 2>&1; then
    gpasswd -d "$u" "$g" >/dev/null 2>&1 || { warn "移除失败（可能本来就不在 $g 组里）"; return 1; }
    info "已将用户 $u 从 $g 组移除"
  elif command -v deluser >/dev/null 2>&1; then
    deluser "$u" "$g" >/dev/null 2>&1 || { warn "移除失败（可能本来就不在 $g 组里）"; return 1; }
    info "已将用户 $u 从 $g 组移除"
  else
    # 兜底：用 usermod -G 重写 supplementary groups（保留其它组）
    local groups new_groups
    groups="$(id -nG "$u" 2>/dev/null || true)"
    [[ -n "$groups" ]] || { warn "无法获取用户组信息"; return 1; }

    new_groups="$(echo "$groups" | tr ' ' '\n' | awk -v rm="$g" '$0!=rm && $0!=""' | paste -sd, -)"
    # usermod -G 设置 supplementary groups；primary group不受影响
    usermod -G "${new_groups}" "$u" || { warn "移除失败（usermod -G）"; return 1; }
    info "已将用户 $u 从 $g 组移除（usermod -G 兜底）"
  fi

  warn "提示：移除组后需要退出并重新登录一次才能在会话中生效。"
}

show_admin_group_members() {
  local g
  g="$(detect_admin_group)"
  [[ -n "$g" ]] || { warn "系统未找到 sudo/wheel 组"; return 1; }

  echo -e "${GREEN}--- ${g} 组成员 ---${NC}"
  getent group "$g" || true

  echo -e "${GREEN}--- sudoers 授权检查（%${g}）---${NC}"
  local hit
  hit="$(grep -RIn --no-messages "^[[:space:]]*%${g}[[:space:]]" /etc/sudoers /etc/sudoers.d 2>/dev/null || true)"
  if [[ -n "$hit" ]]; then
    echo "$hit"
  else
    echo -e "${YELLOW}未找到 %${g} 的 sudoers 授权规则（建议执行：用户管理 -> 修复 sudoers 组授权）${NC}"
  fi
}

# ------------------ fetch（GitHub keys 用） ------------------
check_and_install_fetcher() {
  if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then return 0; fi
  warn "未检测到 curl/wget，正在尝试安装 curl..."
  case "$(detect_pkg_mgr)" in
    apt) apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y curl ;;
    dnf) dnf install -y curl ;;
    yum) yum install -y curl ;;
    *) die "无法识别包管理器，无法自动安装 curl" ;;
  esac
  command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || die "curl/wget 安装失败"
}

fetch_url() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$url"; else wget -qO- "$url"; fi
}

# ------------------ sshd 工具（显式 -f） ------------------
sshd_test_config() { sshd -t -f "$SSHD_CONFIG"; }

sshd_T() {
  # shellcheck disable=SC2086
  sshd -T -f "$SSHD_CONFIG" "$@"
}

get_effective_sshd_value() {
  local key="$1"
  sshd_T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null | awk -v k="$key" '$1==k {print $2; exit}'
}

get_effective_ssh_port() {
  local p
  p="$(get_effective_sshd_value port)"
  [[ -z "$p" ]] && p=22
  echo "$p"
}

ssh_kbd_opt_name() {
  local out
  out="$(sshd_T 2>/dev/null || true)"
  if echo "$out" | grep -qi '^kbdinteractiveauthentication '; then
    echo "KbdInteractiveAuthentication"
  else
    echo "ChallengeResponseAuthentication"
  fi
}

ssh_service_candidates(){ echo "ssh sshd"; }

ssh_reload_or_restart() {
  sshd_test_config || die "sshd 配置检测失败（sshd -t -f ${SSHD_CONFIG}）"

  info "正在 reload/restart SSH 服务..."
  if command -v systemctl >/dev/null 2>&1 && systemctl >/dev/null 2>&1; then
    for svc in $(ssh_service_candidates); do
      if systemctl list-unit-files 2>/dev/null | grep -qE "^${svc}\.service"; then
        systemctl reload "$svc" 2>/dev/null && { info "已通过 systemctl reload ${svc}"; return 0; }
        systemctl restart "$svc" 2>/dev/null && { info "已通过 systemctl restart ${svc}"; return 0; }
      fi
    done
  fi

  if command -v service >/dev/null 2>&1; then
    for svc in $(ssh_service_candidates); do
      service "$svc" status >/dev/null 2>&1 || continue
      service "$svc" reload  >/dev/null 2>&1 && { info "已通过 service ${svc} reload"; return 0; }
      service "$svc" restart >/dev/null 2>&1 && { info "已通过 service ${svc} restart"; return 0; }
    done
  fi

  for svc in $(ssh_service_candidates); do
    [[ -x "/etc/init.d/${svc}" ]] || continue
    "/etc/init.d/${svc}" reload  >/dev/null 2>&1 && { info "已通过 /etc/init.d/${svc} reload"; return 0; }
    "/etc/init.d/${svc}" restart >/dev/null 2>&1 && { info "已通过 /etc/init.d/${svc} restart"; return 0; }
  done

  die "无法 reload/restart SSH 服务"
}

ssh_backup_config() {
  local backup_file="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
  cp "$SSHD_CONFIG" "$backup_file"
  info "SSH 配置已备份：${backup_file}"
  echo "$backup_file"
}

# ------------------ policy state（账号/策略分离） ------------------
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
  case "${1:-}" in
    yes|no) echo "GLOBAL_PASSWORD=$1" >> "$SSH_POLICY_STATE" ;;
    clear) : ;;
    *) die "无效参数：$1" ;;
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

# ------------------ authorized_keys 多密钥 ------------------
get_user_home(){ getent passwd "$1" | awk -F: '{print $6}'; }

authorized_keys_path_for_user() {
  local u="$1" home_dir
  home_dir="$(get_user_home "$u")"
  [[ -n "$home_dir" && -d "$home_dir" ]] || return 1
  echo "${home_dir}/.ssh/authorized_keys"
}

ensure_ssh_dir_permissions() {
  local u="$1" home_dir ssh_dir auth_keys
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
  local line="$1"
  line="$(echo "$line" | tr -d '\r')"
  [[ -z "$line" ]] && return 1
  [[ "$line" =~ ^[[:space:]]*# ]] && return 1
  local t b
  t="$(echo "$line" | awk '{print $1}')"
  b="$(echo "$line" | awk '{print $2}')"
  case "$t" in ssh-*|sk-*) : ;; *) return 1 ;; esac
  [[ "$b" =~ ^[A-Za-z0-9+/=]+$ ]] || return 1
  return 0
}

append_keys_to_user() {
  local u="$1" keys_text="$2"
  id "$u" &>/dev/null || die "用户不存在：$u"
  ensure_ssh_dir_permissions "$u" || die "无法准备 ~/.ssh 权限"
  local auth_keys; auth_keys="$(authorized_keys_path_for_user "$u")" || die "无法获取 authorized_keys 路径"

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

  chown "${u}:${u}" "$auth_keys"; chmod 600 "$auth_keys"
  info "写入完成：新增 ${added}，已存在跳过 ${skipped}，无效行 ${invalid}"
}

clear_user_authorized_keys() {
  local u="$1"
  id "$u" &>/dev/null || die "用户不存在：$u"
  ensure_ssh_dir_permissions "$u" || die "无法准备 ~/.ssh 权限"
  local auth_keys; auth_keys="$(authorized_keys_path_for_user "$u")" || die "无法获取 authorized_keys 路径"
  : > "$auth_keys"
  chown "${u}:${u}" "$auth_keys"; chmod 600 "$auth_keys"
  info "已清空：$auth_keys"
}

show_user_authorized_keys() {
  local u="$1"
  id "$u" &>/dev/null || die "用户不存在：$u"
  local auth_keys; auth_keys="$(authorized_keys_path_for_user "$u")" || die "无法获取 authorized_keys 路径"
  echo -e "${GREEN}--- ${u} 的 authorized_keys：${auth_keys} ---${NC}"
  [[ -f "$auth_keys" ]] && nl -ba "$auth_keys" || echo -e "${YELLOW}文件不存在${NC}"
}

import_pubkeys_interactive() {
  local u="$1" mode="${2:-append}"
  id "$u" &>/dev/null || die "用户不存在：$u"

  if [[ "$mode" == "replace" ]]; then
    warn "将清空该用户现有 authorized_keys 后再导入。"
    confirm "确认继续？" || return 0
    clear_user_authorized_keys "$u"
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
      warn "请粘贴公钥（可多行），输入 END 结束："
      local buf="" line=""
      while IFS= read -r line; do
        [[ "$line" == "END" ]] && break
        buf+="$line"$'\n'
      done
      append_keys_to_user "$u" "$buf"
      ;;
    2)
      read -r -p "请输入公钥文件路径（例如 /root/keys.pub）： " keyfile
      [[ -f "$keyfile" ]] || die "文件不存在：$keyfile"
      append_keys_to_user "$u" "$(cat "$keyfile")"
      ;;
    3)
      check_and_install_fetcher
      read -r -p "请输入 GitHub 用户名： " gh
      if ! [[ "$gh" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$ ]]; then
        die "GitHub 用户名格式看起来不合法"
      fi
      local url keys
      url="https://github.com/${gh}.keys"
      warn "正在拉取：${url}"
      keys="$(fetch_url "$url" 2>/dev/null || true)"
      [[ -n "$keys" ]] || die "未获取到公钥（未公开 key / 网络受限 / 用户名不存在）"
      append_keys_to_user "$u" "$keys"
      ;;
    4) show_user_authorized_keys "$u" ;;
    0) return 0 ;;
    *) warn "无效选择" ;;
  esac
}

manage_user_keys_menu() {
  echo -e "${BLUE}--- 管理用户 authorized_keys（多密钥）---${NC}"
  read -r -p "用户名: " u
  id "$u" &>/dev/null || die "用户不存在，请先在【用户管理】创建"

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
      4) confirm "确认清空 ${u} 的 authorized_keys？" && clear_user_authorized_keys "$u" ;;
      0) break ;;
      *) warn "无效选择" ;;
    esac
  done
}

# ------------------ SFTP-only + chroot ------------------
setup_sftp_chroot_for_user() {
  local u="$1" rootdir="$2"
  id "$u" &>/dev/null || die "用户不存在：$u"
  local upload="${rootdir}/upload"
  mkdir -p "$upload"
  chown root:root "$rootdir"; chmod 755 "$rootdir"
  chown "${u}:${u}" "$upload"; chmod 700 "$upload"
  info "已设置 SFTP chroot：${rootdir}（上传目录：${upload}）"
}

# ------------------ SSH 策略落地到 /etc/ssh/sshd_config.d/99-vpsmgr.conf ------------------
sshd_supports_include_dir() {
  grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONFIG" && [[ -d "$SSHD_CONF_DIR" ]]
}

cleanup_legacy_blocks_in_sshd_config() {
  # 清理旧脚本往 sshd_config 末尾追加的 managed block（避免混乱）
  sed -i "/^${OLD_POLICY_BEGIN}$/,/^${OLD_POLICY_END}$/d" "$SSHD_CONFIG" 2>/dev/null || true
  sed -i "/^${OLD_GLOBAL_BEGIN}$/,/^${OLD_GLOBAL_END}$/d" "$SSHD_CONFIG" 2>/dev/null || true
  sed -i "/^${OLD_USER_BEGIN}$/,/^${OLD_USER_END}$/d" "$SSHD_CONFIG" 2>/dev/null || true

  # 关键：清掉所有非注释 PermitRootLogin（避免被默认 prohibit-password 误导/覆盖）
  sed -i -E '/^[[:space:]]*PermitRootLogin[[:space:]]+/d' "$SSHD_CONFIG" 2>/dev/null || true
}

write_vpsmgr_conf_from_state() {
  policy_state_init
  local kbd_opt; kbd_opt="$(ssh_kbd_opt_name)"

  {
    echo "# Managed by VPSMGR - do not edit manually"
    echo ""
    echo "PermitRootLogin no"
    echo "PubkeyAuthentication yes"
    echo ""
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
  } > "$SSHD_VPSMGR_CONF"

  chmod 0644 "$SSHD_VPSMGR_CONF"
}

ssh_policy_apply() {
  local backup_file
  backup_file="$(ssh_backup_config)"

  if sshd_supports_include_dir; then
    mkdir -p "$SSHD_CONF_DIR"
    cleanup_legacy_blocks_in_sshd_config
    write_vpsmgr_conf_from_state
  else
    warn "系统未启用 Include /etc/ssh/sshd_config.d/*.conf，仍会写 99-vpsmgr.conf 但可能不生效。"
    mkdir -p "$SSHD_CONF_DIR"
    cleanup_legacy_blocks_in_sshd_config
    write_vpsmgr_conf_from_state
  fi

  if ! ssh_reload_or_restart; then
    warn "SSH 重载失败，已回滚。"
    cp "$backup_file" "$SSHD_CONFIG"
    rm -f "$SSHD_VPSMGR_CONF" 2>/dev/null || true
    ssh_reload_or_restart || true
    return 1
  fi

  info "SSH 策略已应用。生效 permitrootlogin：$(get_effective_sshd_value permitrootlogin)"
  return 0
}

ssh_policy_clear_all() {
  local backup_file
  backup_file="$(ssh_backup_config)"
  rm -f "$SSHD_VPSMGR_CONF" 2>/dev/null || true
  rm -f "$SSH_POLICY_STATE" 2>/dev/null || true
  cleanup_legacy_blocks_in_sshd_config

  if ! ssh_reload_or_restart; then
    warn "清理后 SSH 重载失败，已回滚。"
    cp "$backup_file" "$SSHD_CONFIG"
    ssh_reload_or_restart || true
    return 1
  fi
  info "已清理 VPSMGR SSH 策略（99-vpsmgr.conf + state + legacy 清理）"
}

# ------------------ Fail2Ban（安装/启用） ------------------
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
    *) warn "无法识别包管理器，Fail2Ban 安装失败。"; return 1 ;;
  esac

  local ssh_port backend
  ssh_port="$(get_effective_ssh_port)"
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
    info "Fail2Ban 已运行（sshd 端口：${ssh_port}，backend：${backend}）"
  else
    warn "Fail2Ban 可能未运行（非 systemd 环境可能正常）。可尝试：service fail2ban restart"
  fi
}

# 修复 awk 关键字 in：用 in_sshd
update_fail2ban_port_if_present() {
  local new_port="$1"
  local jail="/etc/fail2ban/jail.local"
  [[ -f "$jail" ]] || return 0
  grep -q '^\[sshd\]' "$jail" || return 0

  if awk '
    BEGIN{in_sshd=0; found=0}
    /^\[sshd\]/{in_sshd=1; next}
    /^\[/{in_sshd=0}
    { if(in_sshd && $0 ~ /^port[[:space:]]*=/) found=1 }
    END{ exit(found?0:1) }
  ' "$jail"; then
    awk -v p="$new_port" '
      BEGIN{in_sshd=0}
      /^\[sshd\]/{in_sshd=1; print; next}
      /^\[/{ if(in_sshd){in_sshd=0} print; next}
      {
        if(in_sshd && $0 ~ /^port[[:space:]]*=/){print "port     = " p; next}
        print
      }
    ' "$jail" > "${jail}.tmp" && mv "${jail}.tmp" "$jail"
  else
    awk -v p="$new_port" '
      /^\[sshd\]/{print; print "port     = " p; next}
      {print}
    ' "$jail" > "${jail}.tmp" && mv "${jail}.tmp" "$jail"
  fi

  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet fail2ban 2>/dev/null; then
    systemctl restart fail2ban >/dev/null 2>&1 || true
  elif command -v service >/dev/null 2>&1; then
    service fail2ban restart >/dev/null 2>&1 || true
  fi
}

# ------------------ SSH 端口修改（显示生效端口） ------------------
change_ssh_port() {
  echo -e "${BLUE}--- 修改 SSH 端口 ---${NC}"
  local old_port; old_port="$(get_effective_ssh_port)"
  echo -e "${GREEN}当前 SSH 生效端口：${old_port}${NC}"
  echo -e "${GREEN}当前 sshd_config 中 Port 行：${NC}"
  grep -nE "^\s*#?\s*Port\s+" "$SSHD_CONFIG" || true

  read -r -p "请输入新的SSH端口号 (1-65535): " new_port
  if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
    warn "无效端口号"
    return 1
  fi

  local backup_file; backup_file="$(ssh_backup_config)"

  # 删除所有 Port 行，避免重复；插入到第一个 Match 之前
  sed -i -E '/^\s*#?\s*Port\s+[0-9]+/d' "$SSHD_CONFIG" 2>/dev/null || true

  local tmpout; tmpout="$(mktemp)"
  awk -v P="Port ${new_port}" '
    BEGIN{inserted=0}
    {
      if(!inserted && $0 ~ /^[[:space:]]*Match[[:space:]]+/){
        print P
        inserted=1
      }
      print
    }
    END{ if(!inserted) print P }
  ' "$SSHD_CONFIG" > "$tmpout" && mv "$tmpout" "$SSHD_CONFIG"

  warn "正在测试 SSH 配置..."
  if ! sshd_test_config; then
    warn "SSH 配置测试失败！已回滚。"
    cp "$backup_file" "$SSHD_CONFIG"
    return 1
  fi

  # 防火墙放行（若启用 iptables baseline 链则更新它）
  local firewall_type; firewall_type="$(detect_firewall)"
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
  elif [[ "$firewall_type" == "firewalld" ]]; then
    firewall-cmd --permanent --add-port="${new_port}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi

  echo "正在重载/重启 SSH 服务..."
  if ssh_reload_or_restart; then
    update_fail2ban_port_if_present "$new_port" || true
    info "SSH 端口已修改为: $new_port"
    warn "请使用新端口重新连接！"
  else
    warn "重载/重启 SSH 失败，已回滚。"
    cp "$backup_file" "$SSHD_CONFIG"
    ssh_reload_or_restart || true
    return 1
  fi
}

# ------------------ 用户管理（只管账号，不改 SSH 策略） ------------------
user_management() {
  while true; do
    echo -e "\n===== 用户管理（只管账号，不改 SSH 策略）====="
    echo "1. 新增用户"
    echo "2. 修改用户密码"
    echo "3. 删除用户"
    echo "4. 列出所有用户"
    echo "5. 将现有用户加入 sudo/wheel 组"
    echo "6. 将现有用户移出 sudo/wheel 组"
    echo "7. 查看 sudo/wheel 组成员与 sudoers 授权状态"
    echo "8. 修复 sudoers 组授权（%sudo/%wheel）"
    echo "0. 返回主菜单"
    echo "============================================"
    read -r -p "请选择操作: " user_choice
    case $user_choice in
      1) add_user ;;
      2) change_user_password ;;
      3) delete_user ;;
      4) list_users ;;
      5) read -r -p "用户名: " u; add_user_to_admin_group "$u" ;;
      6) read -r -p "用户名: " u; remove_user_from_admin_group "$u" ;;
      7) show_admin_group_members ;;
      8) ensure_sudo_group_rule ;;
      0) break ;;
      *) warn "无效选择" ;;
    esac
  done
}

add_user() {
  read -r -p "请输入新用户名: " username
  if ! [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    warn "用户名格式不合法"
    return 1
  fi
  id "$username" &>/dev/null && { warn "用户已存在"; return 1; }

  useradd -m -s /bin/bash "$username"
  info "用户 $username 创建成功（仅账号，不含 SSH 策略）"

  if confirm "是否现在为 $username 设置系统密码（用于本机登录/SSH密码/ sudo）？"; then
    passwd "$username"
  else
    warn "未设置密码。若未来要允许 SSH 密码登录或 SFTP-only+密码，请先设置密码。"
  fi

  if confirm "是否将用户 $username 添加到 sudo/wheel 组？"; then
    add_user_to_admin_group "$username" || true
  fi

  warn "下一步：到主菜单【2. SSH 认证策略管理】设置登录策略，并可导入多密钥/从 GitHub 拉取。"
}

change_user_password() {
  read -r -p "请输入要修改密码的用户名: " username
  id "$username" &>/dev/null || { warn "用户不存在"; return 1; }
  passwd "$username"
  info "密码修改成功"
}

delete_user() {
  read -r -p "请输入要删除的用户名: " username
  id "$username" &>/dev/null || { warn "用户不存在"; return 1; }

  local uid
  uid=$(id -u "$username")
  if [ "$uid" -lt 1000 ] && [ "$uid" -ne 0 ]; then
    warn "禁止删除 UID<1000 的系统用户"
    return 1
  fi
  [ "$username" == "root" ] && { warn "禁止删除 root 用户"; return 1; }

  if confirm "确定删除用户 $username 吗？"; then
    if confirm "是否同时删除 /home/$username？"; then
      userdel -r "$username"
      info "用户及主目录已删除"
    else
      userdel "$username"
      info "用户已删除（主目录保留）"
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

# ------------------ SSH 策略菜单（账号/策略分离） ------------------
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
    echo "8. 查看当前策略（state + 生效关键项 + 99-vpsmgr.conf）"
    echo "9. 清理全部 SSH 策略（删除 99-vpsmgr.conf + state）"
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
          *) warn "无效选择"; continue ;;
        esac
        ssh_policy_apply
        ;;
      3)
        read -r -p "用户名: " u
        id "$u" &>/dev/null || { warn "用户不存在，请先在【用户管理】创建"; continue; }
        warn "仅密钥登录前，建议先确保该用户已有公钥（选项7可导入/追加多密钥）。"
        if confirm "是否现在导入/追加该用户公钥？"; then
          import_pubkeys_interactive "$u" "append" || continue
        fi
        policy_state_set_user "$u" "keyonly"
        ssh_policy_apply
        ;;
      4)
        read -r -p "用户名: " u
        id "$u" &>/dev/null || { warn "用户不存在，请先在【用户管理】创建"; continue; }
        warn "此项仅允许 SSH 密码认证，不负责设置系统密码；请到【用户管理->修改用户密码】设置。"
        policy_state_set_user "$u" "password"
        ssh_policy_apply
        ;;
      5)
        read -r -p "用户名(建议 tempuser): " u
        id "$u" &>/dev/null || { warn "用户不存在，请先在【用户管理】创建"; continue; }
        read -r -p "chroot 根目录（默认 /sftp/${u}）: " rootdir
        [[ -z "$rootdir" ]] && rootdir="/sftp/${u}"
        setup_sftp_chroot_for_user "$u" "$rootdir" || continue
        warn "请确保该用户已设置系统密码（用户管理->修改密码），否则无法用密码 SFTP。"
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
        echo -e "${GREEN}--- sshd 最终生效关键项（sshd -T）---${NC}"
        echo "port:              $(get_effective_sshd_value port)"
        echo "permitrootlogin:   $(get_effective_sshd_value permitrootlogin)"
        echo "passwordauth:      $(get_effective_sshd_value passwordauthentication)"
        echo "kbdinteractive:    $(get_effective_sshd_value kbdinteractiveauthentication)"
        echo "pubkeyauth:        $(get_effective_sshd_value pubkeyauthentication)"
        if [[ -f "$SSHD_VPSMGR_CONF" ]]; then
          echo -e "${GREEN}--- ${SSHD_VPSMGR_CONF}（当前生效文件）---${NC}"
          sed -n '1,220p' "$SSHD_VPSMGR_CONF"
        else
          warn "99-vpsmgr.conf 不存在（尚未应用策略或已清理）"
        fi
        ;;
      9)
        confirm "确认清理全部 SSH 策略？" && ssh_policy_clear_all
        ;;
      0) break ;;
      *) warn "无效选择" ;;
    esac
  done
}

# ------------------ iptables 安装/持久化/检测 ------------------
check_and_install_iptables() {
  command -v iptables &>/dev/null && return 0

  warn "检测到 iptables 未安装，正在尝试自动安装..."
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
    *) warn "无法识别包管理器，iptables 安装失败"; return 1 ;;
  esac

  command -v iptables &>/dev/null || { warn "iptables 安装失败或不可用"; return 1; }
  info "iptables 已可用：$(iptables --version 2>/dev/null | head -n1)"
  command -v ip6tables &>/dev/null && info "ip6tables 已可用" || warn "未检测到 ip6tables，将跳过 IPv6 规则"
  return 0
}

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
  command -v iptables-save &>/dev/null || { warn "未找到 iptables-save，无法保存规则"; return 1; }

  if [ -d /etc/iptables ]; then
    iptables-save > /etc/iptables/rules.v4
    command -v ip6tables-save &>/dev/null && ip6tables-save > /etc/iptables/rules.v6 || true
    echo "iptables 规则已保存。"
  elif [ -d /etc/sysconfig ]; then
    iptables-save > /etc/sysconfig/iptables
    command -v ip6tables-save &>/dev/null && ip6tables-save > /etc/sysconfig/ip6tables || true
    echo "iptables 规则已保存。"
  elif command -v apt-get &>/dev/null; then
    warn "为了在重启后保留防火墙规则，建议安装 iptables-persistent。"
    if confirm "是否现在自动安装 iptables-persistent？"; then
      apt-get update >/dev/null 2>&1
      DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent >/dev/null 2>&1 || true
      if [ -d /etc/iptables ]; then
        iptables-save > /etc/iptables/rules.v4
        command -v ip6tables-save &>/dev/null && ip6tables-save > /etc/iptables/rules.v6 || true
        info "安装成功，规则已保存。"
      else
        warn "已尝试安装 iptables-persistent，但未发现 /etc/iptables，请自行确认持久化。"
      fi
    else
      warn "已取消。提示：规则可能不会在重启后保留。"
    fi
  else
    warn "未找到标准保存路径，规则可能不会在重启后保留。"
  fi
}

enable_iptables() {
  echo -e "${GREEN}正在配置 iptables 基础规则 (IPv4 & IPv6)...${NC}"
  check_and_install_iptables || return 1

  local current_ssh_port docker_present mode
  current_ssh_port="$(get_effective_ssh_port)"

  docker_present="no"
  if command -v docker &>/dev/null; then
    iptables -S 2>/dev/null | grep -qE '^-N DOCKER\b' && docker_present="yes"
  fi

  echo -e "${YELLOW}请选择 iptables 初始化模式：${NC}"
  echo "1) 保守模式（推荐）：不清空现有规则，只维护 VPS-BASELINE 链并插入 jump"
  echo "2) 强制重置：清空并重置 filter 规则（可能影响业务；Docker 存在时不建议）"
  read -r -p "请选择(1/2，默认1): " mode
  [[ -z "$mode" ]] && mode="1"

  if [[ "$docker_present" == "yes" && "$mode" == "2" ]]; then
    warn "检测到 Docker：强制重置可能破坏容器网络。已自动降级为保守模式。"
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
      ip6tables -N "$chain" 2>/dev/null || true
      ip6tables -F "$chain" 2>/dev/null || true
      ip6tables -C INPUT -j "$chain" 2>/dev/null || ip6tables -I INPUT 1 -j "$chain"

      ip6tables -A "$chain" -i lo -j ACCEPT
      ip6tables -A "$chain" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      ip6tables -A "$chain" -p tcp --dport "$current_ssh_port" -j ACCEPT
      ip6tables -A "$chain" -p tcp --dport 80 -j ACCEPT
      ip6tables -A "$chain" -p tcp --dport 443 -j ACCEPT
      ip6tables -A "$chain" -p ipv6-icmp -j ACCEPT
      ip6tables -A "$chain" -j RETURN
    fi

    warn "是否把 INPUT 默认策略设为 DROP（更安全但可能影响未放行业务）？"
    if confirm "确认设置 INPUT=DROP？"; then
      iptables -P INPUT DROP
      iptables -P OUTPUT ACCEPT
      if [[ "$docker_present" == "yes" ]]; then
        warn "检测到 Docker：保持 FORWARD 策略不改（避免容器网络异常）"
      else
        iptables -P FORWARD DROP
      fi
      if command -v ip6tables &>/dev/null; then
        ip6tables -P INPUT DROP
        ip6tables -P OUTPUT ACCEPT
        [[ "$docker_present" != "yes" ]] && ip6tables -P FORWARD DROP || true
      fi
    else
      warn "保守模式：未改变默认策略（仅插入允许链）。"
    fi

    save_iptables_rules || true
    info "iptables 保守初始化完成：开放 SSH($current_ssh_port), 80, 443, ICMP；尽量不破坏现有规则"
    return 0
  fi

  warn "强制重置将清空现有 filter 规则。"
  confirm "确定继续？" || { echo "已取消。"; return 0; }

  iptables -F && iptables -X && iptables -Z || { warn "iptables 初始化失败"; return 1; }
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
    ip6tables -F && ip6tables -X && ip6tables -Z || true
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
  info "iptables 已强制重置，默认开放：SSH($current_ssh_port), 80, 443, ICMP"
}

configure_ports() {
  local firewall; firewall="$(detect_firewall)"
  [[ "$firewall" != "none" ]] || { warn "未检测到可用防火墙（iptables/ufw/firewalld）"; return 1; }

  echo "===== 配置防火墙端口 (当前: $firewall) ====="
  echo "1. 开放端口"
  echo "2. 关闭端口"
  read -r -p "请选择操作: " action
  read -r -p "请输入端口号: " port
  if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    warn "无效端口号"
    return 1
  fi
  read -r -p "选择协议 (tcp/udp/both): " protocol
  if [[ "$protocol" != "tcp" && "$protocol" != "udp" && "$protocol" != "both" ]]; then
    warn "无效协议"
    return 1
  fi

  if [[ "$firewall" == "iptables" ]]; then
    local rule_action="-A" op_text="开放"
    [[ "$action" == "2" ]] && rule_action="-D" && op_text="关闭"

    # 若存在 VPS-BASELINE，优先对其操作
    local chain="INPUT"
    iptables -nL VPS-BASELINE >/dev/null 2>&1 && chain="VPS-BASELINE"

    if [[ "$protocol" == "tcp" || "$protocol" == "both" ]]; then
      iptables "$rule_action" "$chain" -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
      command -v ip6tables &>/dev/null && ip6tables "$rule_action" "$chain" -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
      info "iptables: 已${op_text} TCP 端口 $port"
    fi
    if [[ "$protocol" == "udp" || "$protocol" == "both" ]]; then
      iptables "$rule_action" "$chain" -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
      command -v ip6tables &>/dev/null && ip6tables "$rule_action" "$chain" -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
      info "iptables: 已${op_text} UDP 端口 $port"
    fi
    save_iptables_rules || true

  elif [[ "$firewall" == "ufw" ]]; then
    local proto_list=()
    [[ "$protocol" == "tcp" || "$protocol" == "both" ]] && proto_list+=("tcp")
    [[ "$protocol" == "udp" || "$protocol" == "both" ]] && proto_list+=("udp")
    for p in "${proto_list[@]}"; do
      if [[ "$action" == "1" ]]; then
        ufw allow "${port}/${p}" >/dev/null 2>&1 || true
        info "ufw: 已开放 ${port}/${p}"
      else
        ufw delete allow "${port}/${p}" >/dev/null 2>&1 || true
        info "ufw: 已关闭 ${port}/${p}"
      fi
    done

  elif [[ "$firewall" == "firewalld" ]]; then
    local op="--add-port" op_text="开放"
    [[ "$action" == "2" ]] && op="--remove-port" && op_text="关闭"
    if [[ "$protocol" == "tcp" || "$protocol" == "both" ]]; then
      firewall-cmd --permanent "$op=${port}/tcp" >/dev/null 2>&1 || true
      info "firewalld: 已${op_text} ${port}/tcp"
    fi
    if [[ "$protocol" == "udp" || "$protocol" == "both" ]]; then
      firewall-cmd --permanent "$op=${port}/udp" >/dev/null 2>&1 || true
      info "firewalld: 已${op_text} ${port}/udp"
    fi
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

show_firewall_rules() {
  local firewall; firewall="$(detect_firewall)"
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

# ------------------ 端口转发（iptables NAT） ------------------
port_forwarding_menu() {
  if [[ "$(detect_firewall)" != "iptables" ]]; then
    warn "端口转发功能目前仅支持 iptables。"
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
      *) warn "无效选择" ;;
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
  [[ "$proto" == "tcp" || "$proto" == "udp" ]] || { warn "无效协议"; return 1; }

  read -r -p "源端口: " sport
  [[ "$sport" =~ ^[0-9]+$ ]] || { warn "无效源端口"; return 1; }

  read -r -p "目标IP(空=127.0.0.1): " daddr
  [[ -z "$daddr" ]] && daddr="127.0.0.1"

  read -r -p "目标端口: " dport
  [[ "$dport" =~ ^[0-9]+$ ]] || { warn "无效目标端口"; return 1; }

  enable_ip_forwarding

  iptables -t nat -A PREROUTING -p "$proto" --dport "$sport" -j DNAT --to-destination "${daddr}:${dport}" || return 1
  if [[ "$daddr" != "127.0.0.1" ]]; then
    iptables -A FORWARD -p "$proto" -d "$daddr" --dport "$dport" -j ACCEPT || return 1
  fi
  iptables -t nat -A POSTROUTING -p "$proto" -d "$daddr" --dport "$dport" -j MASQUERADE || return 1

  save_iptables_rules || true
  info "已添加转发：$sport -> $daddr:$dport"
}

delete_port_forwarding() {
  echo -e "${BLUE}--- 删除端口转发 ---${NC}"
  read -r -p "协议 (tcp/udp): " proto
  read -r -p "源端口: " sport
  read -r -p "目标IP(空=127.0.0.1): " daddr
  [[ -z "$daddr" ]] && daddr="127.0.0.1"
  read -r -p "目标端口: " dport

  iptables -t nat -D PREROUTING -p "$proto" --dport "$sport" -j DNAT --to-destination "${daddr}:${dport}" 2>/dev/null || true
  [[ "$daddr" != "127.0.0.1" ]] && iptables -D FORWARD -p "$proto" -d "$daddr" --dport "$dport" -j ACCEPT 2>/dev/null || true
  iptables -t nat -D POSTROUTING -p "$proto" -d "$daddr" --dport "$dport" -j MASQUERADE 2>/dev/null || true

  save_iptables_rules || true
  info "已尝试删除转发：$sport -> $daddr:$dport"
}

view_port_forwarding() {
  echo -e "${BLUE}--- 当前 NAT PREROUTING 规则 ---${NC}"
  iptables -t nat -L PREROUTING -n -v --line-numbers
}

# ------------------ Docker 出网策略（DOCKER-USER） ------------------
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
    warn "未发现可清理的 VPSMGR Docker 出网规则。"
    return 0
  fi
  echo "$rules" | sed 's/^-A /-D /' | while read -r line; do
    # shellcheck disable=SC2086
    iptables $line 2>/dev/null || true
  done
  info "已清理 VPSMGR_DOCKER_EGRESS 规则（DOCKER-USER）。"
}

docker_security_menu() {
  echo -e "${BLUE}--- Docker 容器出网安全等级（iptables / DOCKER-USER）---${NC}"
  check_and_install_iptables || return 1
  command -v docker >/dev/null 2>&1 || { warn "未检测到 docker 命令，取消。"; return 1; }

  ensure_docker_user_chain

  local subnets; subnets="$(get_docker_subnets)"
  if [[ -z "$subnets" ]]; then
    warn "未检测到 Docker 子网（docker network inspect 无输出）。仍可用“自定义子网”。"
  else
    info "检测到 Docker 子网："
    echo "$subnets" | sed 's/^/  - /'
  fi

  warn "说明：在 DOCKER-USER 链限制容器发起 NEW 连接的出网行为，较不易被 Docker 规则重排影响。"
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
        info "已设置：所有 Docker 子网仅允许 80/443 发起 NEW 出网，其它 NEW 丢弃。"
      else
        warn "未检测到子网，请用选项 3 自定义子网。"
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
        info "已设置：所有 Docker 子网禁止发起 NEW 出网。"
      else
        warn "未检测到子网，请用选项 3 自定义子网。"
      fi
      save_iptables_rules || true
      ;;
    3)
      read -r -p "输入要限制/放行的子网（例如 172.30.0.0/16）： " net
      [[ -z "$net" ]] && { warn "未输入子网，取消。"; return 1; }

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
        info "已设置：$net 仅允许 80/443 NEW 出网，其它 NEW 丢弃。"
      elif [[ "$m" == "b" ]]; then
        iptables -I DOCKER-USER 1 -s "$net" -m conntrack --ctstate NEW \
          -m comment --comment VPSMGR_DOCKER_EGRESS -j DROP
        info "已设置：$net 禁止 NEW 出网。"
      else
        warn "无效选择"
        return 1
      fi

      save_iptables_rules || true
      ;;
    4) iptables -L DOCKER-USER -n -v --line-numbers ;;
    5) docker_egress_clear_managed_rules; save_iptables_rules || true ;;
    0) return ;;
    *) warn "无效选择" ;;
  esac
}

# ------------------ Caddy 防扫描 snippet ------------------
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

  info "已写入：/etc/caddy/snippets/security.caddy"
  warn "在站点块中使用："
  echo "  import /etc/caddy/snippets/security.caddy"
  echo "  import common_security"
  echo "  # import rate_limit  (若模块不支持请勿启用)"
}

# ------------------ sysctl 网络加固（幂等） ------------------
harden_sysctl() {
  echo -e "${BLUE}--- sysctl 网络安全加固 ---${NC}"
  local marker_begin="# ---- v3.1.0 security hardening BEGIN ----"
  local marker_end="# ---- v3.1.0 security hardening END ----"

  if grep -qF "$marker_begin" "$SYSCTL_CONFIG" 2>/dev/null; then
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
  info "sysctl 加固已应用。"
}

# ------------------ 快速恶意进程检查 ------------------
quick_malware_check() {
  echo -e "${BLUE}--- 快速恶意进程检查 ---${NC}"
  local out
  out=$(ps aux | egrep -i "scanner|masscan|nmap|zmap|check -f|\.\/scanner|\.\/check|socks5|pass\.txt|ok\.list" | grep -v grep || true)
  if [[ -n "$out" ]]; then
    echo -e "${RED}发现可疑进程（仅供线索，建议进一步排查）：${NC}"
    echo "$out"
  else
    info "未发现明显恶意进程特征。"
  fi
}

# ------------------ 一键安全初始化 ------------------
security_init_full() {
  echo -e "${BLUE}=== 一键安全初始化（v3.1.x-TOOLBOX）===${NC}"
  echo -e "${YELLOW}将执行：SSH 安全基线（禁root+全局禁密码） + iptables 初始化 + Fail2Ban + sysctl 加固 + Docker 出网策略 + Caddy 防扫描${NC}"
  confirm "确认继续？" || { echo "操作已取消。"; return; }

  policy_state_set_global_password no
  ssh_policy_apply || return 1

  enable_iptables || true
  install_fail2ban || true
  harden_sysctl || true
  docker_security_menu || true
  install_caddy_security || true

  info "一键安全初始化完成。"
}

# ------------------ 主程序 ------------------
main() {
  check_root
  check_and_install_sudo
  ensure_sudo_group_rule || true
  policy_state_init

  while true; do
    local firewall_type
    firewall_type="$(detect_firewall)"

    clear
    echo "=============================================="
    echo " VPS 高级管理脚本 v3.1.2-TOOLBOX-FINAL (分离版)"
    echo "=============================================="
    echo " 1. 用户管理（账号：新增/删/改密码/sudo）"
    echo " 2. SSH 认证策略管理（仅密钥/密码/SFTP-only/多密钥/GitHub）"
    echo " 3. 修改 SSH 端口（显示生效端口）"
    echo "----------------------------------------------"
    echo " 4. 启用并初始化 iptables 防火墙（保守/强制）"
    echo " 5. 配置防火墙端口 (当前: $firewall_type)"
    echo " 6. 查看当前防火墙规则 (当前: $firewall_type)"
    echo " 7. 端口转发管理 (iptables)"
    echo "----------------------------------------------"
    echo " 8. 安装并启用 Fail2Ban"
    echo " 9. Docker 容器出网安全等级（DOCKER-USER / iptables）"
    echo "10. 生成 Caddy 防扫描规则片段"
    echo "11. sysctl 网络安全加固"
    echo "12. 快速恶意进程检查"
    echo "13. 一键安全初始化（推荐）"
    echo " 0. 退出"
    echo "=============================================="
    read -r -p "请选择功能: " choice

    case "$choice" in
      1) user_management ;;
      2) ssh_policy_menu ;;
      3) change_ssh_port ;;
      4)
        if confirm "将配置 iptables（默认保守模式，不清空现有规则）。继续吗？"; then
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
      *) warn "无效的选择，请重试" ;;
    esac

    read -r -p $'\n按Enter键返回主菜单...'
  done
}

main
