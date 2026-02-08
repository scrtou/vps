#!/bin/bash

# =================================================================
#                         VPS 高级管理脚本 v2.7.1-FULL
#
#   基于: v2.5 (Gemini & User)
#   新增/修复:
#   - [修复] 自动安装 iptables/ip6tables（避免 command not found）
#   - [修复] enable_iptables 成功/失败提示更准确
#   - [新增] Fail2Ban 自动安装+启用（自动读取 SSH 端口）
#   - [新增] Docker 容器出网安全等级菜单（iptables FORWARD）
#   - [新增] Caddy 防扫描/限速 snippet 自动生成
#   - [新增] sysctl 网络安全加固（幂等写入）
#   - [新增] 快速恶意进程检查
#   - [新增] 一键安全初始化（快捷组合，不替代原功能）
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

# --- 自动安装 iptables/ip6tables（修复你遇到的问题）---
check_and_install_iptables() {
  if command -v iptables &>/dev/null; then
    return 0
  fi

  echo -e "${YELLOW}检测到 iptables 未安装，正在尝试自动安装...${NC}"
  case "$(detect_pkg_mgr)" in
    apt)
      apt-get update
      # iptables 会带 ip6tables；iptables-persistent 用于保存规则
      apt-get install -y iptables iptables-persistent
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

# --- 防火墙管理（原有 + 修复） ---
detect_firewall() {
  if command -v firewall-cmd &> /dev/null && systemctl is-active --quiet firewalld; then
    echo "firewalld"
  elif command -v iptables &> /dev/null; then
    if systemctl is-active --quiet iptables || systemctl is-active --quiet netfilter-persistent; then
      echo "iptables"
    else
      echo "iptables (inactive)"
    fi
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
    echo -e "${YELLOW}为了在重启后保留防火墙规则，需要安装 'iptables-persistent'。${NC}"
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

enable_iptables() {
  echo -e "${GREEN}正在配置 iptables 基础规则 (IPv4 & IPv6)...${NC}"
  check_and_install_iptables || return 1

  local current_ssh_port
  current_ssh_port=$(grep -E "^\s*Port\s+" "$SSHD_CONFIG" | awk '{print $2}' | tail -n1)
  [ -z "$current_ssh_port" ] && current_ssh_port=22

  # IPv4
  iptables -F && iptables -X && iptables -Z || { echo -e "${RED}iptables 初始化失败${NC}"; return 1; }
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -p tcp --dport "$current_ssh_port" -j ACCEPT
  iptables -A INPUT -p tcp --dport 80 -j ACCEPT
  iptables -A INPUT -p tcp --dport 443 -j ACCEPT
  iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

  # IPv6（可选）
  if command -v ip6tables &>/dev/null; then
    ip6tables -F && ip6tables -X && ip6tables -Z || { echo -e "${YELLOW}ip6tables 初始化失败，跳过 IPv6 规则${NC}"; }
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT ACCEPT
    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
    ip6tables -A INPUT -p tcp --dport "$current_ssh_port" -j ACCEPT
    ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT
    ip6tables -A INPUT -p tcp --dport 443 -j ACCEPT
  fi

  save_iptables_rules || true
  echo -e "${GREEN}iptables 已启用，默认开放：SSH($current_ssh_port), 80, 443, ICMP${NC}"
}

configure_ports() {
  local firewall
  firewall=$(detect_firewall)
  if [[ "$firewall" == "none" || "$firewall" == "iptables (inactive)" ]]; then
    echo -e "${RED}错误：防火墙服务未激活或 iptables 不可用。${NC}"
    return 1
  fi

  echo "===== 配置防火墙端口 (当前: $firewall) ====="
  echo "1. 开放端口"
  echo "2. 关闭端口"
  read -p "请选择操作: " action
  read -p "请输入端口号: " port
  if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo -e "${RED}错误：无效端口号${NC}"
    return 1
  fi
  read -p "选择协议 (tcp/udp/both): " protocol
  if [[ "$protocol" != "tcp" && "$protocol" != "udp" && "$protocol" != "both" ]]; then
    echo -e "${RED}错误：无效协议${NC}"
    return 1
  fi

  if [[ "$firewall" == "iptables" ]]; then
    local rule_action="-A" op_text="开放"
    [ "$action" == "2" ] && rule_action="-D" && op_text="关闭"

    if [[ "$protocol" == "tcp" || "$protocol" == "both" ]]; then
      iptables "$rule_action" INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null
      command -v ip6tables &>/dev/null && ip6tables "$rule_action" INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
      echo -e "${GREEN}iptables: 已${op_text} TCP 端口 $port${NC}"
    fi
    if [[ "$protocol" == "udp" || "$protocol" == "both" ]]; then
      iptables "$rule_action" INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null
      command -v ip6tables &>/dev/null && ip6tables "$rule_action" INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
      echo -e "${GREEN}iptables: 已${op_text} UDP 端口 $port${NC}"
    fi
    save_iptables_rules || true
  elif [[ "$firewall" == "firewalld" ]]; then
    echo "firewalld 操作暂未实现"
  fi
}

show_firewall_rules() {
  local firewall
  firewall=$(detect_firewall)
  echo -e "${GREEN}--- 当前防火墙规则 ($firewall) ---${NC}"
  case "$firewall" in
    firewalld) firewall-cmd --list-all ;;
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

# --- SSH 管理（原有） ---
change_ssh_port() {
  echo -e "${BLUE}--- 修改 SSH 端口 ---${NC}"
  echo -e "${GREEN}当前 SSH 端口配置：${NC}"
  grep -E "^#?Port" "$SSHD_CONFIG" || true

  read -p "请输入新的SSH端口号 (1-65535): " new_port
  if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
    echo -e "${RED}错误：无效端口号。${NC}"
    return 1
  fi

  if command -v semanage &>/dev/null; then
    echo -e "${YELLOW}检测到 SELinux，正在添加端口策略...${NC}"
    semanage port -a -t ssh_port_t -p tcp "$new_port" &>/dev/null || true
  fi

  local backup_file
  backup_file="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
  cp "$SSHD_CONFIG" "$backup_file"
  echo "配置文件已备份至 $backup_file"

  if grep -q -E "^#?Port" "$SSHD_CONFIG"; then
    sed -i -E "s/^#?Port.*/Port $new_port/" "$SSHD_CONFIG"
  else
    echo "Port $new_port" >> "$SSHD_CONFIG"
  fi

  local firewall_type
  firewall_type=$(detect_firewall)

  if [[ "$firewall_type" == "iptables" ]] && command -v iptables &>/dev/null; then
    echo "正在为 iptables 添加新端口规则..."
    iptables -I INPUT 1 -p tcp --dport "$new_port" -j ACCEPT
    command -v ip6tables &>/dev/null && ip6tables -I INPUT 1 -p tcp --dport "$new_port" -j ACCEPT || true
    save_iptables_rules || true
  elif [[ "$firewall_type" == "firewalld" ]]; then
    echo "正在为 firewalld 添加新端口规则..."
    firewall-cmd --permanent --add-port="$new_port"/tcp > /dev/null
    firewall-cmd --reload > /dev/null
  fi

  echo -e "${YELLOW}正在测试 SSH 配置...${NC}"
  sshd -t
  if [ $? -ne 0 ]; then
    echo -e "${RED}错误：SSH 配置测试失败！已回滚。${NC}"
    mv "$backup_file" "$SSHD_CONFIG"
    return 1
  fi

  local ssh_service_name="sshd"
  systemctl list-units --type=service | grep -q "ssh.service" && ssh_service_name="ssh"

  echo "正在重启 $ssh_service_name ..."
  if systemctl restart "$ssh_service_name"; then
    echo -e "${GREEN}SSH 端口已修改为: $new_port${NC}"
    echo -e "${YELLOW}请使用新端口重新连接！${NC}"
  else
    echo -e "${RED}错误：重启 SSH 服务失败！${NC}"
  fi
}

disable_root_login() {
  echo -e "${BLUE}--- 禁止 root 用户 SSH 登录 ---${NC}"
  echo -e "${YELLOW}继续前请确认存在一个有 sudo 权限的普通用户。${NC}"

  local sudo_users wheel_users
  sudo_users=$(getent group sudo | cut -d: -f4)
  wheel_users=$(getent group wheel | cut -d: -f4)

  if [ -z "$sudo_users" ] && [ -z "$wheel_users" ]; then
    echo -e "${RED}错误：未找到 sudo 或 wheel 组用户。操作中止。${NC}"
    return 1
  else
    echo -e "${GREEN}检测到以下用户拥有 sudo 权限:${NC}"
    echo "$sudo_users$wheel_users" | tr ',' '\n' | sed '/^$/d' | sort -u
  fi

  confirm "确定继续？" || { echo "操作已取消。"; return 0; }

  local backup_file
  backup_file="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
  cp "$SSHD_CONFIG" "$backup_file"

  if grep -q -E "^#?PermitRootLogin" "$SSHD_CONFIG"; then
    sed -i -E 's/^#?PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
  else
    echo "PermitRootLogin no" >> "$SSHD_CONFIG"
  fi

  sshd -t || { echo -e "${RED}SSH 配置测试失败，已回滚。${NC}"; mv "$backup_file" "$SSHD_CONFIG"; return 1; }

  local ssh_service_name="sshd"
  systemctl list-units --type=service | grep -q "ssh.service" && ssh_service_name="ssh"
  systemctl restart "$ssh_service_name" && echo -e "${GREEN}已禁止 root SSH 登录。${NC}" || echo -e "${RED}重启 SSH 失败。${NC}"
}

# --- 用户管理（原有） ---
user_management() {
  while true; do
    echo -e "\n===== 用户管理 ====="
    echo "1. 新增用户"
    echo "2. 修改用户密码"
    echo "3. 删除用户"
    echo "4. 列出所有用户"
    echo "0. 返回主菜单"
    echo "===================="
    read -p "请选择操作: " user_choice
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
  read -p "请输入新用户名: " username
  if ! [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    echo -e "${RED}错误：用户名格式不合法。${NC}"
    return 1
  fi
  id "$username" &>/dev/null && { echo -e "${RED}错误：用户已存在${NC}"; return 1; }

  useradd -m -s /bin/bash "$username"
  echo "请为用户 $username 设置密码:"
  passwd "$username"

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
  echo -e "${GREEN}用户 $username 创建成功${NC}"
}

change_user_password() {
  read -p "请输入要修改密码的用户名: " username
  id "$username" &>/dev/null || { echo -e "${RED}错误：用户不存在${NC}"; return 1; }
  passwd "$username"
  echo -e "${GREEN}密码修改成功${NC}"
}

delete_user() {
  read -p "请输入要删除的用户名: " username
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
  else
    echo "操作已取消。"
  fi
}

list_users() {
  echo -e "${GREEN}--- 系统用户列表（UID >= 1000）---${NC}"
  awk -F: '$3 >= 1000 && $1 != "nobody" {print $1 " (UID: " $3 ")"}' /etc/passwd
}

# --- 端口转发管理（原有） ---
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
    read -p "请选择操作: " choice
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
  sysctl -p "$SYSCTL_CONFIG" >/dev/null
}

add_port_forwarding() {
  echo -e "${BLUE}--- 添加端口转发 ---${NC}"
  read -p "协议 (tcp/udp): " proto
  [[ "$proto" != "tcp" && "$proto" != "udp" ]] && { echo -e "${RED}无效协议${NC}"; return 1; }

  read -p "源端口: " sport
  ! [[ "$sport" =~ ^[0-9]+$ ]] && { echo -e "${RED}无效源端口${NC}"; return 1; }

  read -p "目标IP(空=127.0.0.1): " daddr
  [ -z "$daddr" ] && daddr="127.0.0.1"

  read -p "目标端口: " dport
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
  read -p "协议 (tcp/udp): " proto
  read -p "源端口: " sport
  read -p "目标IP(空=127.0.0.1): " daddr
  [ -z "$daddr" ] && daddr="127.0.0.1"
  read -p "目标端口: " dport

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
# ===================== v2.7.1 新增功能 ==========================
# ================================================================

# --- Fail2Ban 自动安装/启用 ---
install_fail2ban() {
  echo -e "${BLUE}--- 安装并启用 Fail2Ban ---${NC}"
  case "$(detect_pkg_mgr)" in
    apt)
      apt-get update >/dev/null 2>&1
      apt-get install -y fail2ban >/dev/null 2>&1
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

  cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd
ignoreip = 127.0.0.1/8

[sshd]
enabled  = true
port     = ${ssh_port}
EOF

  systemctl enable fail2ban --now
  if systemctl is-active --quiet fail2ban; then
    echo -e "${GREEN}Fail2Ban 已运行（sshd 端口：${ssh_port}）${NC}"
  else
    echo -e "${RED}Fail2Ban 启动失败：journalctl -u fail2ban --no-pager${NC}"
    return 1
  fi
}

# --- Docker 容器出网安全等级菜单（iptables） ---
docker_security_menu() {
  echo -e "${BLUE}--- Docker 容器出网安全等级（iptables）---${NC}"
  check_and_install_iptables || return 1

  echo -e "${YELLOW}说明：通过 FORWARD 链限制容器主动出网（防扫描/肉鸡）。${NC}"
  echo "1. 仅允许 80/443 出网（推荐）"
  echo "2. 完全禁止容器出网（最严格）"
  echo "3. 仅指定 Docker 子网可出网（最灵活）"
  echo "4. 查看当前 FORWARD 规则"
  echo "0. 返回"
  read -p "请选择: " c

  case "$c" in
    1)
      iptables -I FORWARD 1 -s 172.16.0.0/12 -p tcp -m multiport --dports 80,443 -j ACCEPT
      iptables -I FORWARD 2 -s 172.16.0.0/12 -m state --state NEW -j DROP
      echo -e "${GREEN}已设置：容器仅允许 80/443 出网，其它 NEW 禁止。${NC}"
      save_iptables_rules || true
      ;;
    2)
      iptables -I FORWARD 1 -s 172.16.0.0/12 -m state --state NEW -j DROP
      echo -e "${GREEN}已设置：容器完全禁止发起 NEW 出网连接。${NC}"
      save_iptables_rules || true
      ;;
    3)
      read -p "允许出网的子网（如 172.30.0.0/16）: " net
      [ -z "$net" ] && { echo -e "${RED}未输入子网，取消。${NC}"; return 1; }
      iptables -I FORWARD 1 -s "$net" -j ACCEPT
      iptables -I FORWARD 2 -s 172.16.0.0/12 -m state --state NEW -j DROP
      echo -e "${GREEN}已设置：仅允许 $net 出网，其余容器网段禁止 NEW 出网。${NC}"
      save_iptables_rules || true
      ;;
    4) iptables -L FORWARD -n -v --line-numbers ;;
    0) return ;;
    *) echo -e "${RED}无效选择${NC}" ;;
  esac
}

# --- Caddy 防扫描规则片段生成 ---
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
  echo -e "${YELLOW}  import rate_limit${NC}"
}

# --- sysctl 网络加固（幂等） ---
harden_sysctl() {
  echo -e "${BLUE}--- sysctl 网络安全加固 ---${NC}"
  local marker_begin="# ---- v2.7.1 security hardening BEGIN ----"
  local marker_end="# ---- v2.7.1 security hardening END ----"

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

  sysctl -p "$SYSCTL_CONFIG" >/dev/null
  echo -e "${GREEN}sysctl 加固已应用。${NC}"
}

# --- 快速恶意进程检查 ---
quick_malware_check() {
  echo -e "${BLUE}--- 快速恶意进程检查 ---${NC}"
  local out
  out=$(ps aux | egrep -i "scanner|masscan|nmap|zmap|check -f|\.\/scanner|\.\/check|socks5|pass\.txt|ok\.list" | grep -v grep || true)
  if [[ -n "$out" ]]; then
    echo -e "${RED}发现可疑进程（建议立即处理/重装）：${NC}"
    echo "$out"
  else
    echo -e "${GREEN}未发现明显恶意进程特征。${NC}"
  fi
}

# --- 一键安全初始化 ---
security_init_full() {
  echo -e "${BLUE}=== 一键安全初始化（v2.7.1-FULL）===${NC}"
  echo -e "${YELLOW}将执行：Fail2Ban + sysctl 加固 + Docker 出网策略 + 生成 Caddy 防扫描规则${NC}"
  confirm "确认继续？" || { echo "操作已取消。"; return; }

  install_fail2ban || return 1
  harden_sysctl || true
  docker_security_menu || true
  install_caddy_security || true

  echo -e "${GREEN}一键安全初始化完成。${NC}"
}

# --- 主程序 ---
main() {
  check_root
  check_and_install_sudo

  while true; do
    local firewall_type
    firewall_type=$(detect_firewall)

    clear
    echo "========================================="
    echo "       VPS 高级管理脚本 v2.7.1-FULL      "
    echo "========================================="
    echo " 1. 修改SSH端口"
    echo " 2. 禁止 root 用户 SSH 登录"
    echo " 3. 用户管理"
    echo " 4. 启用并初始化iptables防火墙"
    echo " 5. 配置防火墙端口 (当前: $firewall_type)"
    echo " 6. 查看当前防火墙规则 (当前: $firewall_type)"
    echo " 7. 端口转发管理 (iptables)"
    echo "-----------------------------------------"
    echo " 8. 安装并启用 Fail2Ban"
    echo " 9. Docker 容器出网安全等级（iptables）"
    echo "10. 生成 Caddy 防扫描规则片段"
    echo "11. sysctl 网络安全加固"
    echo "12. 快速恶意进程检查"
    echo "13. 一键安全初始化（推荐）"
    echo " 0. 退出"
    echo "========================================="
    read -p "请选择功能: " choice

    case $choice in
      1) change_ssh_port ;;
      2) disable_root_login ;;
      3) user_management ;;
      4)
        if confirm "${YELLOW}此操作将清空现有规则并设置安全默认值，确定吗？${NC}"; then
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

    read -p $'\n按Enter键返回主菜单...'
  done
}

main
