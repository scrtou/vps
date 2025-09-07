#!/bin/bash

# =================================================================
#            VPS 高级管理脚本 v2.3
#
#   作者: Gemini & User
#   更新日期: 2025-09-07
#
#   v2.3 更新日志:
#   - [修复] 为端口转发功能增加了严格的输入验证，防止端口号为空。
#   - [修复] 为iptables命令增加了执行结果检查，失败时会报错并中止。
#   - [修复] 优化了iptables规则的保存逻辑，根据系统类型智能选择路径。
# =================================================================

# --- 全局变量和颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SSHD_CONFIG="/etc/ssh/sshd_config"
SYSCTL_CONFIG="/etc/sysctl.conf"

# --- 核心辅助函数 ---
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误：此脚本需要root权限运行。请尝试使用 'sudo $0'${NC}"
        exit 1
    fi
}
confirm() {
    read -r -p "$1 [y/N] " response
    case "$response" in
        [yY][eE][sS]|[yY]) true ;;
        *) false ;;
    esac
}

# --- SSH 管理 ---
change_ssh_port() {
    echo -e "${BLUE}--- 修改 SSH 端口 ---${NC}"
    echo -e "${GREEN}当前SSH端口配置：${NC}"
    grep -E "^#?Port" "$SSHD_CONFIG"
    read -p "请输入新的SSH端口号 (1-65535): " new_port
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        echo -e "${RED}错误：无效的端口号。${NC}"
        return 1
    fi
    if command -v semanage &> /dev/null; then
        echo -e "${YELLOW}检测到SELinux，正在添加端口策略...${NC}"
        semanage port -a -t ssh_port_t -p tcp "$new_port" &>/dev/null
    fi
    backup_file="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$SSHD_CONFIG" "$backup_file"
    echo "配置文件已备份至 $backup_file"
    if grep -q -E "^#?Port" "$SSHD_CONFIG"; then
        sed -i -E "s/^#?Port.*/Port $new_port/" "$SSHD_CONFIG"
    else
        echo "Port $new_port" >> "$SSHD_CONFIG"
    fi
    firewall_type=$(detect_firewall)
    if [[ "$firewall_type" == "iptables" ]] && (systemctl is-active --quiet iptables || systemctl is-active --quiet netfilter-persistent); then
        echo "正在为 iptables/ip6tables 添加新端口规则..."
        iptables -I INPUT 1 -p tcp --dport "$new_port" -j ACCEPT
        ip6tables -I INPUT 1 -p tcp --dport "$new_port" -j ACCEPT
        save_iptables_rules
    elif [[ "$firewall_type" == "firewalld" ]]; then
        echo "正在为 firewalld 添加新端口规则..."
        firewall-cmd --permanent --add-port="$new_port"/tcp > /dev/null
        firewall-cmd --reload > /dev/null
    fi
    echo -e "${YELLOW}正在测试SSH配置...${NC}"
    sshd -t
    if [ $? -ne 0 ]; then
        echo -e "${RED}错误：SSH配置文件测试失败！操作已自动回滚。${NC}"
        mv "$backup_file" "$SSHD_CONFIG"
        return 1
    fi
    local ssh_service_name="sshd"
    if systemctl list-units --type=service | grep -q "ssh.service"; then
        ssh_service_name="ssh"
    fi
    echo "正在重启 $ssh_service_name 服务..."
    if systemctl restart "$ssh_service_name"; then
        echo -e "${GREEN}SSH端口已成功修改为: $new_port${NC}"
        echo -e "${YELLOW}警告：请确保防火墙已正确开放新端口，并使用新端口重新连接！${NC}"
    else
        echo -e "${RED}错误：重启 $ssh_service_name 服务失败！${NC}"
    fi
}

# --- 用户管理 ---
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
    if id "$username" &>/dev/null; then
        echo -e "${RED}错误：用户 $username 已存在${NC}"
        return 1
    fi
    useradd -m -s /bin/bash "$username"
    echo "请为用户 $username 设置密码:"
    passwd "$username"
    if confirm "是否将用户 $username 添加到 sudo/wheel 组？"; then
        if getent group sudo >/dev/null; then
            usermod -aG sudo "$username"
            echo -e "${GREEN}用户已添加到 sudo 组${NC}"
        elif getent group wheel >/dev/null; then
            usermod -aG wheel "$username"
            echo -e "${GREEN}用户已添加到 wheel 组${NC}"
        else
            echo -e "${YELLOW}警告：未找到 sudo 或 wheel 组。${NC}"
        fi
    fi
    echo -e "${GREEN}用户 $username 创建成功${NC}"
}
change_user_password() {
    read -p "请输入要修改密码的用户名: " username
    if ! id "$username" &>/dev/null; then
        echo -e "${RED}错误：用户 $username 不存在${NC}"
        return 1
    fi
    echo "请为用户 $username 设置新密码:"
    passwd "$username"
    echo -e "${GREEN}密码修改成功${NC}"
}
delete_user() {
    read -p "请输入要删除的用户名: " username
    if ! id "$username" &>/dev/null; then
        echo -e "${RED}错误：用户 $username 不存在${NC}"
        return 1
    fi
    local uid
    uid=$(id -u "$username")
    if [ "$uid" -lt 1000 ] && [ "$uid" -ne 0 ]; then
        echo -e "${RED}错误：出于安全考虑，禁止删除UID低于1000的系统用户。${NC}"
        return 1
    fi
    if [ "$username" == "root" ]; then
        echo -e "${RED}错误：禁止删除 root 用户！${NC}"
        return 1
    fi
    if confirm "${RED}警告：你确定要删除用户 $username 吗？${NC}"; then
        if confirm "是否同时删除用户的主目录 (/home/$username)？"; then
            userdel -r "$username"
            echo -e "${GREEN}用户 $username 及其主目录已删除${NC}"
        else
            userdel "$username"
            echo -e "${GREEN}用户 $username 已删除（主目录保留）${NC}"
        fi
    else
        echo "操作已取消。"
    fi
}
list_users() {
    echo -e "${GREEN}--- 系统用户列表（UID >= 1000） ---${NC}"
    awk -F: '$3 >= 1000 && $1 != "nobody" {print $1 " (UID: " $3 ")"}' /etc/passwd
}

# --- 防火墙管理 ---
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
enable_iptables() {
    echo -e "${GREEN}正在配置iptables基础规则 (IPv4 & IPv6)...${NC}"
    current_ssh_port=$(grep -E "^Port" "$SSHD_CONFIG" | awk '{print $2}')
    [ -z "$current_ssh_port" ] && current_ssh_port=22
    iptables -F && iptables -X && iptables -Z
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport "$current_ssh_port" -j ACCEPT
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
    ip6tables -F && ip6tables -X && ip6tables -Z
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT ACCEPT
    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
    ip6tables -A INPUT -p tcp --dport "$current_ssh_port" -j ACCEPT
    ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT
    ip6tables -A INPUT -p tcp --dport 443 -j ACCEPT
    save_iptables_rules
    echo -e "${GREEN}iptables & ip6tables 已启用，默认开放端口：SSH($current_ssh_port), 80, 443, ICMP${NC}"
}
configure_ports() {
    local firewall
    firewall=$(detect_firewall)
    if [[ "$firewall" == "none" || "$firewall" == "iptables (inactive)" ]]; then
        echo -e "${RED}错误：防火墙服务未激活。${NC}"
        return 1
    fi
    echo "===== 配置防火墙端口 (当前使用: $firewall) ====="
    echo "1. 开放端口"
    echo "2. 关闭端口"
    read -p "请选择操作: " action
    read -p "请输入端口号: " port
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo -e "${RED}错误：无效的端口号${NC}"
        return 1
    fi
    read -p "选择协议 (tcp/udp/both): " protocol
    if [[ "$protocol" != "tcp" && "$protocol" != "udp" && "$protocol" != "both" ]]; then
        echo -e "${RED}错误：无效的协议。${NC}"
        return 1
    fi
    if [[ "$firewall" == "iptables" ]]; then
        rule_action="-A" && op_text="开放"
        [ "$action" == "2" ] && rule_action="-D" && op_text="关闭"
        if [[ "$protocol" == "tcp" || "$protocol" == "both" ]]; then
            iptables "$rule_action" INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null
            ip6tables "$rule_action" INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null
            echo -e "${GREEN}iptables/ip6tables: 已${op_text} TCP 端口 $port${NC}"
        fi
        if [[ "$protocol" == "udp" || "$protocol" == "both" ]]; then
            iptables "$rule_action" INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null
            ip6tables "$rule_action" INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null
            echo -e "${GREEN}iptables/ip6tables: 已${op_text} UDP 端口 $port${NC}"
        fi
        save_iptables_rules
        echo "Iptables 规则已保存。"
    elif [[ "$firewall" == "firewalld" ]]; then
        echo "firewalld 操作暂未实现"
    fi
}
save_iptables_rules() {
    if command -v iptables-save &> /dev/null; then
        if [ -d /etc/iptables ]; then
            iptables-save > /etc/iptables/rules.v4
            ip6tables-save > /etc/iptables/rules.v6
        elif [ -d /etc/sysconfig ]; then
            iptables-save > /etc/sysconfig/iptables
            ip6tables-save > /etc/sysconfig/ip6tables
        else
            echo -e "${YELLOW}警告: 未找到标准的iptables规则保存路径。规则可能不会在重启后保留。${NC}"
        fi
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
            echo -e "\n${BLUE}--- IPv6 (ip6tables) ---${NC}"
            ip6tables -L -n -v --line-numbers
            ;;
        *) echo "没有活动的防火墙服务。" ;;
    esac
}
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
    read -p "请输入协议 (tcp/udp): " proto
    if [[ "$proto" != "tcp" && "$proto" != "udp" ]]; then
        echo -e "${RED}错误: 无效的协议。${NC}"
        return 1
    fi

    read -p "请输入源端口 (外网访问的端口): " sport
    if ! [[ "$sport" =~ ^[0-9]+$ ]] || [ "$sport" -lt 1 ] || [ "$sport" -gt 65535 ]; then
        echo -e "${RED}错误: 源端口无效。${NC}"
        return 1
    fi

    read -p "请输入目标IP (本机请留空或输入127.0.0.1): " daddr
    [ -z "$daddr" ] && daddr="127.0.0.1"

    read -p "请输入目标端口 (服务监听的端口): " dport
    if ! [[ "$dport" =~ ^[0-9]+$ ]] || [ "$dport" -lt 1 ] || [ "$dport" -gt 65535 ]; then
        echo -e "${RED}错误: 目标端口无效。${NC}"
        return 1
    fi

    echo "正在启用IP转发..."
    enable_ip_forwarding

    echo "正在添加NAT规则..."
    iptables -t nat -A PREROUTING -p "$proto" --dport "$sport" -j DNAT --to-destination "${daddr}:${dport}"
    if [ $? -ne 0 ]; then
        echo -e "${RED}错误: 添加PREROUTING规则失败！${NC}"
        return 1
    fi

    if [[ "$daddr" != "127.0.0.1" ]]; then
        iptables -A FORWARD -p "$proto" -d "$daddr" --dport "$dport" -j ACCEPT
        if [ $? -ne 0 ]; then
            echo -e "${RED}错误: 添加FORWARD规则失败！${NC}"
            return 1
        fi
    fi

    iptables -t nat -A POSTROUTING -p "$proto" -d "$daddr" --dport "$dport" -j MASQUERADE
    if [ $? -ne 0 ]; then
        echo -e "${RED}错误: 添加POSTROUTING规则失败！${NC}"
        return 1
    fi

    save_iptables_rules
    echo -e "${GREEN}成功添加并保存端口转发规则: $sport -> $daddr:$dport ${NC}"
}
delete_port_forwarding() {
    echo -e "${BLUE}--- 删除端口转发 (请确保参数与添加时完全一致) ---${NC}"
    read -p "请输入协议 (tcp/udp): " proto
    read -p "请输入源端口 (外网访问的端口): " sport
    read -p "请输入目标IP (本机请留空或输入127.0.0.1): " daddr
    [ -z "$daddr" ] && daddr="127.0.0.1"
    read -p "请输入目标端口 (服务监听的端口): " dport
    iptables -t nat -D PREROUTING -p "$proto" --dport "$sport" -j DNAT --to-destination "${daddr}:${dport}" 2>/dev/null
    if [[ "$daddr" != "127.0.0.1" ]]; then
        iptables -D FORWARD -p "$proto" -d "$daddr" --dport "$dport" -j ACCEPT 2>/dev/null
    fi
    iptables -t nat -D POSTROUTING -p "$proto" -d "$daddr" --dport "$dport" -j MASQUERADE 2>/dev/null
    save_iptables_rules
    echo -e "${GREEN}尝试删除转发规则: $sport -> $daddr:$dport (如果规则存在，则已删除)${NC}"
}
view_port_forwarding() {
    echo -e "${BLUE}--- 当前NAT PREROUTING规则 ---${NC}"
    iptables -t nat -L PREROUTING -n -v --line-numbers
}

# --- 主程序 ---
main() {
    check_root
    while true; do
        firewall_type=$(detect_firewall)
        clear
        echo "========================================="
        echo "         VPS 高级管理脚本 v2.3           "
        echo "========================================="
        echo " 1. 修改SSH端口"
        echo " 2. 用户管理"
        echo " 3. 启用并初始化iptables防火墙"
        echo " 4. 配置防火墙端口 (当前: $firewall_type)"
        echo " 5. 查看当前防火墙规则 (当前: $firewall_type)"
        echo " 6. 端口转发管理 (iptables)"
        echo " 0. 退出"
        echo "========================================="
        read -p "请选择功能: " choice
        case $choice in
            1) change_ssh_port ;;
            2) user_management ;;
            3) if confirm "${YELLOW}此操作将清空现有规则并设置安全默认值，确定吗？${NC}"; then enable_iptables; else echo "操作已取消。"; fi ;;
            4) configure_ports ;;
            5) show_firewall_rules ;;
            6) port_forwarding_menu ;;
            0) echo "退出脚本"; exit 0 ;;
            *) echo -e "${RED}无效的选择，请重试${NC}"; sleep 2 ;;
        esac
        if [[ "$choice" -ne 2 && "$choice" -ne 6 && "$choice" -ne 0 ]]; then
             read -p $'\n按Enter键返回主菜单...'
        fi
    done
}

# --- 脚本入口 ---
main
