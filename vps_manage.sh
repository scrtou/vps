#!/bin/bash

# =================================================================
#            VPS 高级管理脚本 v2.0
#
#   功能:
#   - SSH 端口安全管理 (支持 SELinux, 配置预检测)
#   - 用户管理 (防误删系统用户)
#   - 防火墙管理 (自动检测并支持 iptables 和 firewalld)
# =================================================================

# --- 全局变量和颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SSHD_CONFIG="/etc/ssh/sshd_config"

# --- 核心辅助函数 ---

# 检查是否以root权限运行
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误：此脚本需要root权限运行。请尝试使用 'sudo $0'${NC}"
        exit 1
    fi
}

# 通用的确认函数
confirm() {
    # $1: 提示信息
    read -r -p "$1 [y/N] " response
    case "$response" in
        [yY][eE][sS]|[yY])
            true
            ;;
        *)
            false
            ;;
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
        semanage port -a -t ssh_port_t -p tcp "$new_port"
        if [ $? -ne 0 ]; then
            echo -e "${YELLOW}警告：添加SELinux端口策略失败。可能是端口已存在或需要安装 'policycoreutils-python-utils'。脚本将继续...${NC}"
        fi
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
    if [[ "$firewall_type" == "iptables" ]] && systemctl is-active --quiet iptables; then
        echo "正在为 iptables 添加新端口规则..."
        iptables -I INPUT 1 -p tcp --dport "$new_port" -j ACCEPT
        save_iptables_rules
    elif [[ "$firewall_type" == "firewalld" ]] && systemctl is-active --quiet firewalld; then
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
        echo -e "${RED}错误：重启 $ssh_service_name 服务失败！请手动检查配置和服务状态。${NC}"
    fi
}

# --- 用户管理 ---

user_management() {
    while true; do
        echo ""
        echo "===== 用户管理 ====="
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
        echo -e "${RED}错误：用户名格式不合法。请使用小写字母、数字、下划线和连字符。${NC}"
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
    
    if confirm "${RED}警告：你确定要删除用户 $username 吗？此操作不可恢复！${NC}"; then
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
        # 即使iptables存在，也要检查服务是否在运行
        if systemctl is-active --quiet iptables || systemctl is-active --quiet netfilter-persistent; then
            echo "iptables"
        else
            # firewalld未运行，iptables服务也未运行，但iptables命令存在
            echo "iptables (inactive)"
        fi
    else
        echo "none"
    fi
}

enable_iptables() {
    echo -e "${GREEN}正在配置iptables基础规则...${NC}"
    
    if ! command -v iptables-persistent &> /dev/null; then
        echo "正在安装 iptables-persistent..."
        if command -v apt-get &>/dev/null; then
            apt-get update && apt-get install -y iptables-persistent
        elif command -v yum &>/dev/null; then
            yum install -y iptables-services
            systemctl enable iptables
        fi
    fi
    
    current_ssh_port=$(grep -E "^Port" "$SSHD_CONFIG" | awk '{print $2}')
    [ -z "$current_ssh_port" ] && current_ssh_port=22
    
    # 清空规则
    iptables -F && iptables -X && iptables -Z
    
    # 默认策略
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # 基础规则
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # 开放端口
    iptables -A INPUT -p tcp --dport "$current_ssh_port" -j ACCEPT # SSH
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT  # HTTP
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT # HTTPS
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT # Ping
    
    save_iptables_rules
    
    if command -v systemctl &> /dev/null; then
        systemctl restart netfilter-persistent 2>/dev/null || systemctl restart iptables 2>/dev/null
    fi
    
    echo -e "${GREEN}iptables已启用，默认开放端口：SSH($current_ssh_port), 80, 443, ICMP${NC}"
}

configure_ports() {
    local firewall
    firewall=$(detect_firewall)

    if [[ "$firewall" == "none" || "$firewall" == "iptables (inactive)" ]]; then
        echo -e "${RED}错误：防火墙服务未激活。请先从主菜单启用。${NC}"
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
        echo -e "${RED}错误：无效的协议。请输入 tcp, udp, 或 both。${NC}"
        return 1
    fi

    # --- Firewalld 逻辑 ---
    if [[ "$firewall" == "firewalld" ]]; then
        protocols_to_process=()
        [[ "$protocol" == "tcp" || "$protocol" == "both" ]] && protocols_to_process+=("tcp")
        [[ "$protocol" == "udp" || "$protocol" == "both" ]] && protocols_to_process+=("udp")

        for p in "${protocols_to_process[@]}"; do
            if [ "$action" == "1" ]; then
                firewall-cmd --permanent --add-port="$port/$p" > /dev/null
                echo -e "${GREEN}firewalld: 规则已添加，将在重载后开放 ${p^^} 端口 $port${NC}"
            elif [ "$action" == "2" ]; then
                firewall-cmd --permanent --remove-port="$port/$p" > /dev/null
                echo -e "${GREEN}firewalld: 规则已移除，将在重载后关闭 ${p^^} 端口 $port${NC}"
            else
                echo -e "${RED}无效操作${NC}"; return 1
            fi
        done
        firewall-cmd --reload
        echo "Firewalld 已重载。"
    # --- Iptables 逻辑 ---
    elif [[ "$firewall" == "iptables" ]]; then
        rule_action="-A" && op_text="开放"
        [ "$action" == "2" ] && rule_action="-D" && op_text="关闭"

        if [[ "$protocol" == "tcp" || "$protocol" == "both" ]]; then
            iptables "$rule_action" INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null
            echo -e "${GREEN}iptables: 已${op_text} TCP 端口 $port${NC}"
        fi
        if [[ "$protocol" == "udp" || "$protocol" == "both" ]]; then
            iptables "$rule_action" INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null
            echo -e "${GREEN}iptables: 已${op_text} UDP 端口 $port${NC}"
        fi
        save_iptables_rules
        echo "Iptables 规则已保存。"
    fi
}

save_iptables_rules() {
    if command -v iptables-save &> /dev/null; then
        # Debian/Ubuntu
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
        # RHEL/CentOS
        iptables-save > /etc/sysconfig/iptables 2>/dev/null
    fi
}

show_firewall_rules() {
    local firewall
    firewall=$(detect_firewall)

    echo -e "${GREEN}--- 当前防火墙规则 ($firewall) ---${NC}"
    case "$firewall" in
        firewalld)
            firewall-cmd --list-all
            ;;
        iptables)
            iptables -L -n -v --line-numbers
            ;;
        *)
            echo "没有活动的防火墙服务。"
            ;;
    esac
}

# --- 主程序 ---
main() {
    check_root
    
    while true; do
        firewall_type=$(detect_firewall)
        clear
        echo "========================================="
        echo "         VPS 高级管理脚本 v2.0           "
        echo "========================================="
        echo " 1. 修改SSH端口"
        echo " 2. 用户管理"
        echo " 3. 启用并初始化iptables防火墙"
        echo " 4. 配置防火墙端口 (当前: $firewall_type)"
        echo " 5. 查看当前防火墙规则 (当前: $firewall_type)"
        echo " 0. 退出"
        echo "========================================="
        
        read -p "请选择功能: " choice
        
        case $choice in
            1) change_ssh_port ;;
            2) user_management ;;
            3) 
                if confirm "${YELLOW}此操作将清空现有iptables规则并设置一套安全默认值，确定吗？${NC}"; then
                    enable_iptables
                else
                    echo "操作已取消。"
                fi
                ;;
            4) configure_ports ;;
            5) show_firewall_rules ;;
            0) echo "退出脚本"; exit 0 ;;
            *) echo -e "${RED}无效的选择，请重试${NC}"; sleep 2 ;;
        esac
        
        # 用户管理有自己的循环和暂停
        if [[ "$choice" -ne 2 && "$choice" -ne 0 ]]; then
             read -p $'\n按Enter键返回主菜单...'
        fi
    done
}

# --- 脚本入口 ---
main
