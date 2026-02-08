#!/bin/bash
# =================================================================
# VPS 高级管理脚本 v2.7-FULL
# 基于 v2.5，新增：
# - Fail2Ban
# - Docker 容器安全等级
# - Caddy 防扫描规则
# - sysctl 网络加固
# - 恶意进程快速检查
# =================================================================

# ---------- 颜色 ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SSHD_CONFIG="/etc/ssh/sshd_config"
SYSCTL_CONFIG="/etc/sysctl.conf"

# ---------- 基础 ----------
check_root() {
    [[ $EUID -ne 0 ]] && echo -e "${RED}需要 root 权限运行${NC}" && exit 1
}

confirm() {
    read -r -p "$1 [y/N] " r
    [[ "$r" =~ ^[yY]$ ]]
}

check_and_install_sudo() {
    command -v sudo &>/dev/null && return
    echo -e "${YELLOW}正在安装 sudo...${NC}"
    if command -v apt-get &>/dev/null; then
        apt-get update && apt-get install -y sudo
    elif command -v yum &>/dev/null; then
        yum install -y sudo
    elif command -v dnf &>/dev/null; then
        dnf install -y sudo
    else
        echo -e "${RED}无法安装 sudo${NC}"
        exit 1
    fi
}

# ================================================================
# 🔐 Fail2Ban
# ================================================================
install_fail2ban() {
    echo -e "${BLUE}--- 安装 Fail2Ban ---${NC}"

    if ! command -v fail2ban-client &>/dev/null; then
        if command -v apt-get &>/dev/null; then
            apt-get update && apt-get install -y fail2ban
        elif command -v yum &>/dev/null; then
            yum install -y fail2ban
        elif command -v dnf &>/dev/null; then
            dnf install -y fail2ban
        fi
    fi

    SSH_PORT=$(grep -E "^Port" "$SSHD_CONFIG" | awk '{print $2}')
    [ -z "$SSH_PORT" ] && SSH_PORT=22

cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = $SSH_PORT
EOF

    systemctl enable fail2ban --now
    echo -e "${GREEN}Fail2Ban 已启用 (SSH:$SSH_PORT)${NC}"
}

# ================================================================
# 🐳 Docker 容器安全等级
# ================================================================
docker_security_menu() {
    echo -e "${BLUE}--- Docker 容器出网安全等级 ---${NC}"
    echo "1. 仅允许 80/443 出网（推荐）"
    echo "2. 完全禁止容器出网"
    echo "3. 仅指定 Docker 子网可出网"
    echo "0. 返回"
    read -p "选择: " c

    case $c in
        1)
            iptables -I FORWARD -s 172.16.0.0/12 -p tcp -m multiport --dports 80,443 -j ACCEPT
            iptables -I FORWARD -s 172.16.0.0/12 -m state --state NEW -j DROP
            ;;
        2)
            iptables -I FORWARD -s 172.16.0.0/12 -m state --state NEW -j DROP
            ;;
        3)
            read -p "允许出网的子网 (如 172.30.0.0/16): " net
            iptables -I FORWARD -s "$net" -j ACCEPT
            iptables -I FORWARD -s 172.16.0.0/12 -m state --state NEW -j DROP
            ;;
    esac
    echo -e "${GREEN}Docker 出网策略已更新${NC}"
}

# ================================================================
# 🌐 Caddy 防扫描
# ================================================================
install_caddy_security() {
    mkdir -p /etc/caddy/snippets
cat >/etc/caddy/snippets/security.caddy <<'EOF'
(common_security) {
    @bad_ua {
        header_regexp User-Agent (?i)(nmap|masscan|zgrab|sqlmap|curl|wget|python)
    }
    respond @bad_ua 403

    @bad_path {
        path_regexp bad (\.env|\.git|wp-admin|phpmyadmin|\.sql|\.bak)
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
    echo -e "${GREEN}Caddy 防扫描规则已生成${NC}"
}

# ================================================================
# 🧠 sysctl 网络加固
# ================================================================
harden_sysctl() {
cat >>"$SYSCTL_CONFIG"<<EOF

# ---- Security hardening ----
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
EOF
    sysctl -p >/dev/null
    echo -e "${GREEN}sysctl 网络加固完成${NC}"
}

# ================================================================
# 🚨 快速恶意进程检查
# ================================================================
quick_malware_check() {
    echo -e "${BLUE}--- 快速恶意进程检查 ---${NC}"
    ps aux | egrep -i "scanner|masscan|nmap|check -f|\.\/[a-z]{4,}" | grep -v grep \
        && echo -e "${RED}⚠️ 发现可疑进程${NC}" \
        || echo -e "${GREEN}未发现明显恶意进程${NC}"
}

# ================================================================
# ⭐ 一键安全初始化（不影响原功能）
# ================================================================
security_init_full() {
    install_fail2ban
    harden_sysctl
    docker_security_menu
    install_caddy_security
    echo -e "${GREEN}v2.7-FULL 安全初始化完成${NC}"
}

# ================================================================
# 🔁 主菜单（原菜单 + 新增）
# ================================================================
main() {
    check_root
    check_and_install_sudo

    while true; do
        clear
        echo "========================================="
        echo "     VPS 高级管理脚本 v2.7-FULL"
        echo "========================================="
        echo " 1. 修改 SSH 端口"
        echo " 2. 禁止 root 用户 SSH 登录"
        echo " 3. 用户管理"
        echo " 4. 启用并初始化 iptables"
        echo " 5. 配置防火墙端口"
        echo " 6. 查看防火墙规则"
        echo " 7. 端口转发管理 (iptables)"
        echo "-----------------------------------------"
        echo " 8. 安装并启用 Fail2Ban"
        echo " 9. Docker 容器安全等级"
        echo "10. 安装 Caddy 防扫描规则"
        echo "11. sysctl 网络加固"
        echo "12. 快速恶意进程检查"
        echo "13. 一键安全初始化 (推荐)"
        echo " 0. 退出"
        echo "========================================="
        read -p "请选择: " c

        case $c in
            8) install_fail2ban ;;
            9) docker_security_menu ;;
            10) install_caddy_security ;;
            11) harden_sysctl ;;
            12) quick_malware_check ;;
            13) security_init_full ;;
            0) exit ;;
            *) echo "原有功能保持不变，请使用原菜单项" ;;
        esac
        read -p "回车继续..."
    done
}

main
