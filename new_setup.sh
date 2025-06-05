#!/usr/bin/env bash
# Debian/Ubuntu 一键开发环境配置脚本 (优化版)
# 支持root用户运行、自动配置sudo、修复PATH、SSH配置、脚本内GitHub链接代理等
# 融合了优化的Docker安装和系统检查功能
# 新增：支持根据地区配置镜像源和代理

set -euo pipefail
trap 'echo -e "\033[0;31m[ERROR]\033[0m 第${LINENO}行命令执行失败：${BASH_COMMAND}"; exit 1' ERR

# 色彩输出
RED='\033[0;31m'; GREEN='\033[32;1m'
YELLOW='\033[33;1m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; PURPLE='\033[0;35m'
NC='\033[0m'

# 全局变量
IS_ROOT=false
TARGET_USER=""
TARGET_HOME=""
SUDO_CMD=""
INSTALL_EXTRA_TOOLS=false

# 中国大陆地区配置控制
IN_CHINA="${IN_CHINA:-auto}"

log_info()    { echo -e "${BLUE}[INFO]${NC}    $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC}   $*"; }
log_step()    { echo -e "${PURPLE}[STEP]${NC}    $*"; }
log_prompt()  { echo -e "${CYAN}[PROMPT]${NC}  $*"; }

# 检测是否在中国大陆
detect_china_region() {
  if [[ "${IN_CHINA}" == "auto" ]]; then
    log_info "自动检测地区..."
    
    # 方法1: 检查时区
    local timezone=""
    if [[ -f /etc/timezone ]]; then
      timezone=$(cat /etc/timezone 2>/dev/null || echo "")
    elif command -v timedatectl &>/dev/null; then
      timezone=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "")
    fi
    
    if [[ "${timezone}" =~ ^Asia/(Shanghai|Chongqing|Harbin|Urumqi)$ ]]; then
      IN_CHINA="true"
      log_info "检测到中国时区: ${timezone}"
      return
    fi
    
    # 方法2: 检查语言环境
    if [[ "${LANG:-}" =~ ^zh_CN ]]; then
      IN_CHINA="true"
      log_info "检测到中文语言环境: ${LANG}"
      return
    fi
    
    # 方法3: 尝试网络检测（简单方法，可能不准确）
    if command -v curl &>/dev/null; then
      local ip_info=""
      # 使用可靠的IP地理位置服务，设置短超时
      if ip_info=$(curl -s --connect-timeout 3 --max-time 5 "http://ipinfo.io/country" 2>/dev/null); then
        if [[ "${ip_info}" == "CN" ]]; then
          IN_CHINA="true"
          log_info "检测到中国IP地址"
          return
        fi
      fi
    fi
    
    # 默认不在中国
    IN_CHINA="false"
    log_info "未检测到中国大陆环境，使用国际配置"
  else
    log_info "使用手动指定的地区配置: ${IN_CHINA}"
  fi
}

# GitHub 代理前缀（仅在中国时启用）
get_github_proxy() {
  if [[ "${IN_CHINA}" == "true" ]]; then
    echo "${GITHUB_PROXY:-https://ghfast.top}"
  else
    echo ""
  fi
}

# Docker相关配置
REGISTRY_MIRROR="${REGISTRY_MIRROR:-auto}"
DOCKER_VERSION="${DOCKER_VERSION:-28.2.2}"
DOCKER_COMPOSE_VERSION="${DOCKER_COMPOSE_VERSION:-v2.36.2}"

# 支持更多 GitHub 相关域名
add_github_proxy() {
  local url="$1"
  local proxy_prefix=$(get_github_proxy)
  
  if [[ -n "${proxy_prefix}" && "${url}" =~ ^https://(github\.com|raw\.githubusercontent\.com|api\.github\.com|codeload\.github\.com|objects\.githubusercontent\.com|ghcr\.io|gist\.github\.com) ]]; then
    echo "${proxy_prefix}/${url}"
  else
    echo "${url}"
  fi
}

# 检查URL是否为GitHub相关域名
is_github_url() {
  local url="$1"
  [[ "${url}" =~ ^https://(github\.com|raw\.githubusercontent\.com|api\.github\.com|codeload\.github\.com|objects\.githubusercontent\.com|ghcr\.io|gist\.github\.com) ]]
}

# 处理脚本文件中的GitHub链接，添加代理前缀
process_script_github_urls() {
  local script_file="$1"
  local backup_file="${script_file}.backup"
  local proxy_prefix=$(get_github_proxy)

  if [[ ! -f "${script_file}" ]]; then
    log_warning "脚本文件不存在: ${script_file}"
    return 1
  fi

  # 如果没有设置代理，直接返回
  if [[ -z "${proxy_prefix}" ]]; then
    log_info "未启用GitHub代理，跳过脚本链接处理"
    return 0
  fi

  log_info "处理脚本中的GitHub链接: $(basename "${script_file}")"

  # 备份原文件
  cp "${script_file}" "${backup_file}"

  # 使用sed替换GitHub相关域名
  sed -i "
    # 处理 https://github.com
    s|https://github\.com|${proxy_prefix}/https://github.com|g
    # 处理 https://raw.githubusercontent.com
    s|https://raw\.githubusercontent\.com|${proxy_prefix}/https://raw.githubusercontent.com|g
    # 处理 https://api.github.com
    s|https://api\.github\.com|${proxy_prefix}/https://api.github.com|g
    # 处理 https://codeload.github.com
    s|https://codeload\.github\.com|${proxy_prefix}/https://codeload.github.com|g
    # 处理 https://objects.githubusercontent.com
    s|https://objects\.githubusercontent\.com|${proxy_prefix}/https://objects.githubusercontent.com|g
    # 处理 https://ghcr.io
    s|https://ghcr\.io|${proxy_prefix}/https://ghcr.io|g
    # 处理 https://gist.github.com
    s|https://gist\.github\.com|${proxy_prefix}/https://gist.github.com|g
    # 移除重复的代理前缀（防止多次处理导致的重复）
    s|${proxy_prefix}/${proxy_prefix}/|${proxy_prefix}/|g
  " "${script_file}"

  log_success "脚本GitHub链接处理完成: $(basename "${script_file}")"
}

# 下载并处理脚本的通用函数
download_and_process_script() {
  local url="$1"
  local output_file="$2"
  local process_github_urls="${3:-auto}"

  log_info "下载脚本: ${url}"

  # 下载脚本
  curl -fsSL "$(add_github_proxy "${url}")" -o "${output_file}"
  chmod +x "${output_file}"

  # 决定是否处理GitHub链接
  local should_process=false
  if [[ "${process_github_urls}" == "true" ]]; then
    should_process=true
  elif [[ "${process_github_urls}" == "auto" ]] && is_github_url "${url}"; then
    should_process=true
  fi

  # 处理脚本中的GitHub链接
  if [[ "${should_process}" == "true" ]]; then
    process_script_github_urls "${output_file}"
  fi

  log_success "脚本下载和处理完成: $(basename "${output_file}")"
}

# 初始化用户信息和sudo命令
init_user_info() {
  if [[ "${EUID}" -eq 0 ]]; then
    IS_ROOT=true
    log_info "检测到以root用户运行"

    # 尝试从环境变量获取实际用户
    if [[ -n "${SUDO_USER:-}" ]]; then
      TARGET_USER="${SUDO_USER}"
    else
      # 询问目标用户
      while [[ -z "${TARGET_USER}" ]]; do
        read -rp "请输入要配置开发环境的用户名: " TARGET_USER_INPUT
        if ! id "${TARGET_USER_INPUT}" &>/dev/null; then
          log_error "用户 ${TARGET_USER_INPUT} 不存在"
        else
          TARGET_USER="${TARGET_USER_INPUT}"
        fi
      done
    fi

    TARGET_HOME=$(eval echo "~${TARGET_USER}")
    SUDO_CMD=""
    log_info "目标用户: ${TARGET_USER}, HOME: ${TARGET_HOME}"
  else
    IS_ROOT=false
    TARGET_USER="${USER}"
    TARGET_HOME="${HOME}"
    SUDO_CMD="sudo"
    log_info "检测到普通用户运行: ${TARGET_USER}"
  fi
}

# 用户选择配置项
configure_installation_options() {
  log_step "配置安装选项"
  
  echo ""
  log_prompt "额外开发工具包括："
  echo "  • Node.js (LTS)"
  echo "  • Python3-pip, JDK, Go, Ruby, PHP"
  echo "  • 数据库客户端 (MySQL, PostgreSQL, Redis, SQLite)"
  echo "  • 开发工具 (jq, yq)"
  echo "  • Visual Studio Code"
  echo ""
  
  read -rp "是否安装额外开发工具？ (y/N): " install_extra
  if [[ "${install_extra,,}" == "y" ]]; then
    INSTALL_EXTRA_TOOLS=true
    log_success "已选择安装额外开发工具"
  else
    log_info "跳过额外开发工具安装"
  fi
  
  echo ""
}

# 状态文件
get_status_file() {
  echo "${TARGET_HOME}/.dev-env-setup-status"
}

mark_completed()   { echo "$1" >> "$(get_status_file)"; }
is_completed()     { [[ -f "$(get_status_file)" ]] && grep -qx "$1" "$(get_status_file)"; }
skip_if_completed(){ is_completed "$1" && log_warning "$1 已完成，跳过。" && return 0 || return 1; }

# 修复PATH环境变量
fix_path() {
  skip_if_completed "fix_path" && return
  log_step "检查并修复PATH环境变量"

  local common_paths=(
    "/usr/local/sbin"
    "/usr/local/bin"
    "/usr/sbin"
    "/usr/bin"
    "/sbin"
    "/bin"
    "/snap/bin"
  )

  local current_path="${PATH}"
  local new_paths=()

  for path_to_check in "${common_paths[@]}"; do
    if [[ ":${current_path}:" != *":${path_to_check}:"* ]] && [[ -d "${path_to_check}" ]]; then
      new_paths+=("${path_to_check}")
    fi
  done

  if [[ ${#new_paths[@]} -gt 0 ]]; then
    log_info "添加缺失的PATH: ${new_paths[*]}"

    export PATH="${PATH}:$(IFS=:; echo "${new_paths[*]}")"
    log_info "当前会话PATH已更新: ${PATH}"

    local profile_content=""
    for path_to_add in "${new_paths[@]}"; do
      profile_content+="export PATH=\"\$PATH:${path_to_add}\"\n"
    done

    echo -e "${profile_content}" | ${SUDO_CMD} tee -a /etc/profile >/dev/null
    log_info "PATH配置已写入 /etc/profile"
  fi

  log_success "PATH检查完成"
  mark_completed "fix_path"
}

# 检查并安装sudo
setup_sudo() {
  skip_if_completed "setup_sudo" && return
  log_step "配置sudo和用户权限"

  if [[ "${IS_ROOT}" == "true" ]]; then
    if ! command -v sudo &>/dev/null; then
      log_info "安装sudo..."
      apt update
      apt install -y sudo
    fi

    if ! groups "${TARGET_USER}" | grep -qw sudo; then
      log_info "将用户 ${TARGET_USER} 添加到sudo组..."
      if command -v usermod &>/dev/null; then
        usermod -aG sudo "${TARGET_USER}"
      else
        /usr/sbin/usermod -aG sudo "${TARGET_USER}"
      fi
    fi

    if ! grep -q "^%sudo" /etc/sudoers; then
      echo "%sudo ALL=(ALL:ALL) ALL" >> /etc/sudoers
    fi

    log_success "sudo配置完成"
  else
    if ! command -v sudo &>/dev/null; then
      log_error "sudo未安装，请先以root用户运行此脚本或手动安装sudo"
      exit 1
    fi

    if ! sudo -n true 2>/dev/null; then
      log_warning "当前用户无sudo权限，某些操作可能失败"
      read -rp "是否继续？(y/N): " yn
      [[ "${yn,,}" == "y" ]] || exit 1
    fi
  fi

  mark_completed "setup_sudo"
}

# 执行命令的包装函数
run_as_user() {
  local cmd="$*"
  if [[ "${IS_ROOT}" == "true" ]]; then
    su - "${TARGET_USER}" -c "cd '${TARGET_HOME}' && ${cmd}"
  else
    (cd "${TARGET_HOME}" && eval "${cmd}")
  fi
}

# 创建目录的包装函数
create_user_dir() {
  local dir_path="$1"
  if [[ "${IS_ROOT}" == "true" ]]; then
    mkdir -p "${dir_path}"
    chown "${TARGET_USER}:${TARGET_USER}" "${dir_path}"
  else
    mkdir -p "${dir_path}"
  fi
}

# 写入用户文件的包装函数
write_user_file() {
  local file_path="$1"
  local content="$2"
  if [[ "${IS_ROOT}" == "true" ]]; then
    echo -e "${content}" > "${file_path}"
    chown "${TARGET_USER}:${TARGET_USER}" "${file_path}"
  else
    echo -e "${content}" > "${file_path}"
  fi
}

# 检查系统类型和依赖
check_system() {
  command -v apt >/dev/null \
    || { log_error "此脚本仅支持基于 apt 的系统（Debian/Ubuntu）。"; exit 1; }
  log_info "检测到支持的系统类型"

  # 检查系统信息
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    log_info "系统信息: ${PRETTY_NAME:-${ID} ${VERSION_ID}}"
  fi
}

# 检查iptables（Docker依赖）
check_iptables() {
  log_info "检查iptables..."

  if [[ -e /usr/sbin/iptables ]] || [[ -e /sbin/iptables ]]; then
    log_success "iptables已安装"
  else
    log_info "iptables未安装，尝试安装..."

    if [[ -f /etc/os-release ]]; then
      . /etc/os-release
      case "${ID,,}" in
        debian)
          if [[ "${VERSION_ID}" == "11" ]] || [[ "${VERSION_ID}" == "12" ]]; then
            ${SUDO_CMD} apt update
            ${SUDO_CMD} apt install -y iptables iptables-persistent
            log_success "iptables安装完成"
          else
            log_error "不支持的Debian版本，请手动安装iptables"
            exit 1
          fi
          ;;
        ubuntu)
          ${SUDO_CMD} apt update
          ${SUDO_CMD} apt install -y iptables iptables-persistent
          log_success "iptables安装完成"
          ;;
        *)
          log_error "不支持的系统类型，请手动安装iptables"
          exit 1
          ;;
      esac
    else
      log_error "无法确定系统类型，请手动安装iptables"
      exit 1
    fi
  fi
}

# ---- 步骤 1：配置 SSH ----
setup_ssh() {
  skip_if_completed "setup_ssh" && return
  log_step "配置SSH服务"

  log_info "配置 SSH：允许 root 登录，并启用密码认证…"

  local cfg="/etc/ssh/sshd_config"
  ${SUDO_CMD} cp -n "${cfg}" "${cfg}.backup" 2>/dev/null || true

  ${SUDO_CMD} sed -i \
    -e 's/^#\?\s*PermitRootLogin\s\+.*/PermitRootLogin yes/' \
    -e 's/^#\?\s*PasswordAuthentication\s\+.*/PasswordAuthentication yes/' \
    "${cfg}"

  if command -v systemctl &>/dev/null; then
    ${SUDO_CMD} systemctl restart ssh
  else
    ${SUDO_CMD} /bin/systemctl restart ssh
  fi

  log_success "SSH 配置完成：root 用户可登录，密码认证已启用。"
  mark_completed "setup_ssh"
}

# ---- 步骤 2：生成SSH密钥对并配置免密登录 ----
setup_ssh_keys() {
  skip_if_completed "setup_ssh_keys" && return
  log_step "配置SSH密钥对"

  log_info "生成SSH密钥对并配置免密登录..."

  local ssh_dir="${TARGET_HOME}/.ssh"
  local private_key="${ssh_dir}/id_rsa"
  local public_key="${ssh_dir}/id_rsa.pub"
  local authorized_keys="${ssh_dir}/authorized_keys"

  create_user_dir "${ssh_dir}"

  if [[ "${IS_ROOT}" == "true" ]]; then
    chmod 700 "${ssh_dir}"
    chown -R "${TARGET_USER}:${TARGET_USER}" "${ssh_dir}"
  else
    chmod 700 "${ssh_dir}"
  fi

  if [[ ! -f "${private_key}" ]]; then
    log_info "生成SSH密钥对..."
    run_as_user "ssh-keygen -t rsa -b 4096 -f '${private_key}' -N '' -C '${TARGET_USER}@$(hostname)'"
    log_success "SSH密钥对生成完成"
  else
    log_warning "SSH密钥对已存在，跳过生成"
  fi

  if [[ -f "${public_key}" ]]; then
    log_info "配置authorized_keys..."

    if [[ ! -f "${authorized_keys}" ]]; then
       run_as_user "touch '${authorized_keys}'"
    fi

    local pub_content
    pub_content=$(run_as_user "cat '${public_key}'")
    if ! run_as_user "grep -Fq -- '${pub_content}' '${authorized_keys}'"; then
      run_as_user "echo '${pub_content}' >> '${authorized_keys}'"
      log_info "公钥已添加到authorized_keys"
    else
      log_warning "公钥已存在于authorized_keys中"
    fi

    run_as_user "chmod 600 '${authorized_keys}'"
    run_as_user "chmod 600 '${private_key}'"
  fi

  log_info "测试SSH连接到localhost..."
  run_as_user "ssh-keyscan -H 127.0.0.1 >> '${ssh_dir}/known_hosts' 2>/dev/null || true"
  run_as_user "ssh-keyscan -H localhost >> '${ssh_dir}/known_hosts' 2>/dev/null || true"
  run_as_user "sort -u -o '${ssh_dir}/known_hosts' '${ssh_dir}/known_hosts'"

  local test_cmd="ssh -o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=no ${TARGET_USER}@127.0.0.1 'echo SSH连接测试成功'"
  if run_as_user "${test_cmd}" 2>/dev/null; then
    log_success "SSH免密登录测试成功"
  else
    log_warning "SSH免密登录测试失败，但密钥已配置完成"
  fi

  log_success "SSH密钥配置完成"
  mark_completed "setup_ssh_keys"
}

# ---- 步骤 3：切换到阿里云源 (仅在中国时执行) ----
setup_aliyun_mirror() {
  skip_if_completed "aliyun_mirror" && return
  
  if [[ "${IN_CHINA}" != "true" ]]; then
    log_info "非中国大陆地区，跳过阿里云镜像源配置"
    mark_completed "aliyun_mirror"
    return
  fi
  
  log_step "配置阿里云镜像源"
  
  log_info "备份并配置阿里云镜像源…"
  ${SUDO_CMD} cp -n /etc/apt/sources.list /etc/apt/sources.list.backup

  . /etc/os-release
  local codename="${VERSION_CODENAME}"
  if [[ "${ID,,}" == "ubuntu" ]]; then
    ${SUDO_CMD} tee /etc/apt/sources.list >/dev/null <<EOF
deb https://mirrors.aliyun.com/ubuntu/ ${codename} main restricted universe multiverse
deb-src https://mirrors.aliyun.com/ubuntu/ ${codename} main restricted universe multiverse
deb https://mirrors.aliyun.com/ubuntu/ ${codename}-security main restricted universe multiverse
deb-src https://mirrors.aliyun.com/ubuntu/ ${codename}-security main restricted universe multiverse
deb https://mirrors.aliyun.com/ubuntu/ ${codename}-updates main restricted universe multiverse
deb-src https://mirrors.aliyun.com/ubuntu/ ${codename}-updates main restricted universe multiverse
deb https://mirrors.aliyun.com/ubuntu/ ${codename}-backports main restricted universe multiverse
deb-src https://mirrors.aliyun.com/ubuntu/ ${codename}-backports main restricted universe multiverse
EOF
  elif [[ "${ID,,}" == "debian" ]]; then
    ${SUDO_CMD} tee /etc/apt/sources.list >/dev/null <<EOF
deb https://mirrors.aliyun.com/debian/ ${codename} main non-free contrib
deb-src https://mirrors.aliyun.com/debian/ ${codename} main non-free contrib
deb https://mirrors.aliyun.com/debian-security/ ${codename}-security main
deb-src https://mirrors.aliyun.com/debian-security/ ${codename}-security main
deb https://mirrors.aliyun.com/debian/ ${codename}-updates main non-free contrib
deb-src https://mirrors.aliyun.com/debian/ ${codename}-updates main non-free contrib
deb https://mirrors.aliyun.com/debian/ ${codename}-backports main non-free contrib
deb-src https://mirrors.aliyun.com/debian/ ${codename}-backports main non-free contrib
EOF
  else
    log_warning "未知发行版 ${ID}，跳过镜像源配置。"
    return
  fi

  log_success "阿里云镜像源配置完成。"
  mark_completed "aliyun_mirror"
}

# ---- 步骤 4：更新系统 ----
update_system() {
  skip_if_completed "system_update" && return
  log_step "更新系统"
  
  log_info "更新 apt 包列表并升级…"
  ${SUDO_CMD} apt update && ${SUDO_CMD} apt upgrade -y
  log_success "系统更新完成。"
  mark_completed "system_update"
}

# ---- 步骤 5：安装基础工具 ----
install_basic_tools() {
  skip_if_completed "basic_tools" && return
  log_step "安装基础工具"
  
  log_info "安装基础工具 (curl, wget, git, vim, jq, …) …"
  ${SUDO_CMD} apt install -y \
    curl wget git vim build-essential software-properties-common \
    apt-transport-https ca-certificates gnupg lsb-release unzip \
    tree htop neofetch fontconfig openssh-server jq
  log_success "基础工具安装完成。"
  mark_completed "basic_tools"
}

# ---- 步骤 6：安装并配置 Zsh & Oh My Zsh & Powerlevel10k ----
install_zsh() {
  skip_if_completed "zsh" && return
  log_step "安装Zsh"
  
  log_info "安装 zsh…"
  ${SUDO_CMD} apt install -y zsh

  if [[ "$(getent passwd "${TARGET_USER}" | cut -d: -f7)" != "$(command -v zsh)" ]]; then
    log_info "切换用户 ${TARGET_USER} 的默认 shell 到 zsh…"
    if command -v chsh &>/dev/null; then
      ${SUDO_CMD} chsh -s "$(command -v zsh)" "${TARGET_USER}"
    else
      ${SUDO_CMD} /usr/bin/chsh -s "$(command -v zsh)" "${TARGET_USER}"
    fi
    log_warning "用户 ${TARGET_USER} 需要重新登录以使 shell 更改生效。"
  fi
  log_success "zsh 安装完成。"
  mark_completed "zsh"
}

install_oh_my_zsh() {
  skip_if_completed "oh_my_zsh" && return
  log_step "安装Oh My Zsh"
  
  log_info "安装 Oh My Zsh…"
  if [[ ! -d "${TARGET_HOME}/.oh-my-zsh" ]]; then
    local url install_script
    url='https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh'
    install_script="$(mktemp --tmpdir ohmyzsh_install.XXXXXX.sh)"

    download_and_process_script "${url}" "${install_script}" "auto"

    run_as_user "RUNZSH=no CHSH=no KEEP_ZSHRC=yes sh '${install_script}' --unattended"

    rm -f "${install_script}"
    log_success "Oh My Zsh 安装完成。"
  else
    log_warning "Oh My Zsh 已存在，跳过。"
  fi
  mark_completed "oh_my_zsh"
}

install_powerlevel10k() {
  skip_if_completed "powerlevel10k" && return
  log_step "安装Powerlevel10k主题"
  
  log_info "安装 Powerlevel10k…"
  local dest="${TARGET_HOME}/.oh-my-zsh/custom/themes/powerlevel10k"
  if [[ ! -d "${dest}" ]]; then
    create_user_dir "$(dirname "${dest}")"
    run_as_user "git clone --depth=1 '$(add_github_proxy 'https://github.com/romkatv/powerlevel10k.git')' '${dest}'"

    local zshrc_file="${TARGET_HOME}/.zshrc"
    if [[ -f "${zshrc_file}" ]]; then
        if run_as_user "grep -q '^ZSH_THEME=' '${zshrc_file}'"; then
            run_as_user "sed -i 's|^ZSH_THEME=.*|ZSH_THEME=\"powerlevel10k/powerlevel10k\"|' '${zshrc_file}'"
        else
            run_as_user "echo 'ZSH_THEME=\"powerlevel10k/powerlevel10k\"' >> '${zshrc_file}'"
        fi
    else
        write_user_file "${zshrc_file}" "export ZSH=\"${TARGET_HOME}/.oh-my-zsh\"\nZSH_THEME=\"powerlevel10k/powerlevel10k\"\nplugins=(git)\nsource \$ZSH/oh-my-zsh.sh\n"
    fi

    local p10k_instant_prompt_cmd='if [[ -r "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh" ]]; then source "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh"; fi'
    if ! run_as_user "grep -Fq '${p10k_instant_prompt_cmd}' '${zshrc_file}'"; then
        run_as_user "echo '${p10k_instant_prompt_cmd}' | cat - '${zshrc_file}' > /tmp/zshrc_temp && mv /tmp/zshrc_temp '${zshrc_file}'"
        if [[ "$IS_ROOT" == "true" ]]; then chown "${TARGET_USER}:${TARGET_USER}" "${zshrc_file}"; fi
    fi

    if ! run_as_user "grep -q 'POWERLEVEL9K_DISABLE_CONFIGURATION_WIZARD' '${zshrc_file}'"; then
       run_as_user "echo 'typeset -g POWERLEVEL9K_DISABLE_CONFIGURATION_WIZARD=true' >> '${zshrc_file}'"
    fi

    log_success "Powerlevel10k 安装完成。"
  else
    log_warning "Powerlevel10k 已存在，跳过。"
  fi
  mark_completed "powerlevel10k"
}

# ---- 步骤 7：配置 Vim (使用 Catppuccin 浅色主题) ----
configure_vim() {
  skip_if_completed "vim" && return
  log_step "配置Vim (Catppuccin浅色主题)"
  
  log_info "配置 Vim 使用 Catppuccin 浅色主题…"
  
  # 创建vim配置目录
  local vim_dir="${TARGET_HOME}/.vim"
  local colors_dir="${vim_dir}/colors"
  
  create_user_dir "${vim_dir}"
  create_user_dir "${colors_dir}"
  
  # 克隆 Catppuccin vim 主题
  local catppuccin_tmp_dir="$(mktemp -d)"
  log_info "下载 Catppuccin vim 主题..."
  run_as_user "git clone --depth=1 '$(add_github_proxy 'https://github.com/catppuccin/vim.git')' '${catppuccin_tmp_dir}'"
  
  # 复制颜色文件
  if [[ "${IS_ROOT}" == "true" ]]; then
    cp -r "${catppuccin_tmp_dir}/colors/"* "${colors_dir}/"
    chown -R "${TARGET_USER}:${TARGET_USER}" "${colors_dir}"
  else
    run_as_user "cp -r '${catppuccin_tmp_dir}/colors/'* '${colors_dir}/'"
  fi
  
  rm -rf "${catppuccin_tmp_dir}"
  
  # 创建 .vimrc 配置文件
  local vimrc_content='
" 启用真彩色支持
set termguicolors

" 基本设置
set number
set relativenumber
set expandtab
set tabstop=4
set shiftwidth=4
set smartindent
set autoindent
set hlsearch
set incsearch
set ignorecase
set smartcase
set wildmenu
set ruler
set showcmd
set laststatus=2
set backspace=indent,eol,start
set encoding=utf-8
set fileencodings=utf-8,gb2312,gb18030,gbk,ucs-bom,cp936,latin1

" 启用语法高亮
syntax enable

" 设置 Catppuccin 浅色主题
colorscheme catppuccin_latte

" 启用文件类型检测
filetype on
filetype plugin on
filetype indent on

" 鼠标支持
set mouse=a

" 搜索高亮
set hlsearch
" 按 ESC 清除搜索高亮
nnoremap <ESC> :nohlsearch<CR>

" 显示匹配的括号
set showmatch

" 自动补全
set wildmode=longest,list,full

" 历史记录
set history=1000

" 状态栏显示
set statusline=%F%m%r%h%w\ [FORMAT=%{&ff}]\ [TYPE=%Y]\ [POS=%l,%v][%p%%]\ %{strftime(\"%d/%m/%y\ -\ %H:%M\")}

" 快捷键映射
" 保存文件
nnoremap <C-s> :w<CR>
inoremap <C-s> <Esc>:w<CR>a

" 退出
nnoremap <C-q> :q<CR>

" 复制到系统剪贴板
vnoremap <C-c> "+y

" 从系统剪贴板粘贴
nnoremap <C-v> "+p
inoremap <C-v> <Esc>"+pa

" 窗口切换
nnoremap <C-h> <C-w>h
nnoremap <C-j> <C-w>j
nnoremap <C-k> <C-w>k
nnoremap <C-l> <C-w>l

" 标签页操作
nnoremap <C-t> :tabnew<CR>
nnoremap <C-w> :tabclose<CR>
nnoremap <C-PageUp> :tabprev<CR>
nnoremap <C-PageDown> :tabnext<CR>

" 文件树 (如果安装了 netrw)
nnoremap <F2> :Explore<CR>

" 缩进操作
vnoremap < <gv
vnoremap > >gv

" 行移动
nnoremap <A-j> :m .+1<CR>==
nnoremap <A-k> :m .-2<CR>==
inoremap <A-j> <Esc>:m .+1<CR>==gi
inoremap <A-k> <Esc>:m .-2<CR>==gi
vnoremap <A-j> :m '\''>+1<CR>gv=gv
vnoremap <A-k> :m '\''<-2<CR>gv=gv
'

  write_user_file "${TARGET_HOME}/.vimrc" "${vimrc_content}"
  
  log_success "Vim 配置完成 (Catppuccin 浅色主题)。"
  log_info "主题: catppuccin_latte (浅色)"
  log_info "配置文件: ${TARGET_HOME}/.vimrc"
  mark_completed "vim"
}

# ---- 步骤 8：安装并配置 tmux ----
install_tmux() {
  skip_if_completed "tmux" && return
  log_step "安装tmux"
  
  log_info "安装 tmux…"
  ${SUDO_CMD} apt install -y tmux
  log_success "tmux 安装完成。"
  mark_completed "tmux"
}

configure_tmux() {
  skip_if_completed "tmux_conf" && return
  log_step "配置tmux"
  
  log_info "配置 tmux…"
  local tmux_plugins_dir="${TARGET_HOME}/.tmux/plugins"
  create_user_dir "${tmux_plugins_dir}"

  if [[ ! -d "${tmux_plugins_dir}/tpm" ]]; then
    run_as_user "git clone --depth=1 '$(add_github_proxy 'https://github.com/tmux-plugins/tpm')' '${tmux_plugins_dir}/tpm'"
  else
    log_warning "TPM (Tmux Plugin Manager) 已存在，跳过克隆。"
  fi

  write_user_file "${TARGET_HOME}/.tmux.conf" '# 保留默认前缀 Ctrl+b
set -g mouse on
set -g history-limit 10000
set -g base-index 1
setw -g pane-base-index 1
set -g renumber-windows on
set-option -g detach-on-destroy off

bind r source-file ~/.tmux.conf \; display "tmux 配置已重载"
bind | split-window -h -c "#{pane_current_path}"
bind - split-window -v -c "#{pane_current_path}"
bind h select-pane -L
bind j select-pane -D
bind k select-pane -U
bind l select-pane -R

# List of plugins
set -g @plugin '\''tmux-plugins/tpm'\''
set -g @plugin '\''tmux-plugins/tmux-sensible'\''
set -g @plugin '\''catppuccin/tmux'\''
set -g @catppuccin_flavour '\''latte'\''

# Initialize TMUX plugin manager (keep this line at the very bottom of tmux.conf)
run '\''~/.tmux/plugins/tpm/tpm'\'''

  log_success "tmux 配置完成，请在 tmux 下按 前缀 + I (例如 Ctrl+b I) 安装插件。"
  log_info "tmux主题: Catppuccin Latte (浅色)"
  mark_completed "tmux_conf"
}

# ---- 步骤 9：安装 Miniconda ----
install_miniconda() {
  skip_if_completed "miniconda" && return
  log_step "安装Miniconda"
  
  log_info "安装 Miniconda…"

  if run_as_user "command -v conda" &>/dev/null; then
    log_warning "conda 已存在于PATH中，跳过。"
    mark_completed "miniconda"
    return
  fi

  if run_as_user "[ -d '${TARGET_HOME}/miniconda3/bin' ] && [ -x '${TARGET_HOME}/miniconda3/bin/conda' ]"; then
    log_warning "Miniconda 已安装在 ${TARGET_HOME}/miniconda3，跳过。"
    log_info "确保 conda 已为 zsh 和 bash 初始化..."
    run_as_user "'${TARGET_HOME}/miniconda3/bin/conda' init zsh || true"
    run_as_user "'${TARGET_HOME}/miniconda3/bin/conda' init bash || true"
    mark_completed "miniconda"
    return
  fi

  local arch url installer_path
  arch="$(uname -m)"
  if [[ "${arch}" == "x86_64" ]]; then
    url="https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh"
  elif [[ "${arch}" == "aarch64" ]]; then
    url="https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-aarch64.sh"
  else
    log_error "不支持的架构：${arch}"; return 1
  fi

  installer_path="$(mktemp --tmpdir miniconda_installer.XXXXXX.sh)"

  log_info "下载 Miniconda 安装脚本..."
  curl -fsSL "${url}" -o "${installer_path}"
  chmod +x "${installer_path}"

  log_info "以用户 ${TARGET_USER} 身份执行 Miniconda 安装..."
  run_as_user "'${installer_path}' -b -p '${TARGET_HOME}/miniconda3'"
  rm -f "${installer_path}"

  run_as_user "'${TARGET_HOME}/miniconda3/bin/conda' init zsh"
  run_as_user "'${TARGET_HOME}/miniconda3/bin/conda' init bash"

  log_success "Miniconda 安装完成。"
  mark_completed "miniconda"
}

# 获取Docker镜像源配置
get_docker_registry_mirrors() {
  if [[ "${REGISTRY_MIRROR}" == "auto" ]]; then
    if [[ "${IN_CHINA}" == "true" ]]; then
      echo "CN"
    else
      echo "NONE"
    fi
  else
    echo "${REGISTRY_MIRROR}"
  fi
}

# ---- 步骤 10：安装 Docker (融合优化版本) ----
install_docker() {
  skip_if_completed "docker" && return
  log_step "安装Docker"
  
  log_info "安装 Docker…"

  # 检查Docker是否已安装并运行
  if systemctl is-active --quiet docker 2>/dev/null; then
    local docker_version
    docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
    local docker_ver_major docker_ver_minor
    docker_ver_major=$(echo "$docker_version" | awk -F "." '{print $1}')
    docker_ver_minor=$(echo "$docker_version" | awk -F "." '{print $2}')

    if [[ "$docker_ver_major" == "1" && "$docker_ver_minor" == "12" ]]; then
      log_error "检测到Docker版本过低($docker_version)，请升级到1.13.x或更高版本"
      exit 1
    else
      log_warning "Docker已安装并运行，版本: $docker_version"
      mark_completed "docker"
      return
    fi
  fi

  # 确保iptables已安装（Docker依赖）
  check_iptables

  local arch docker_version url cache_file tgzdir
  arch="$(uname -m)"
  case "${arch}" in
    x86_64)   arch="x86_64" ;;
    aarch64)  arch="aarch64" ;;
    armv7l)   arch="armhf" ;;
    *)        log_error "不支持的架构：${arch}"; return 1 ;;
  esac

  # 获取Docker版本号
  if [[ -n "${DOCKER_VERSION:-}" ]]; then
    docker_version="${DOCKER_VERSION}"
    log_info "使用环境变量指定的Docker版本: ${docker_version}"
  else
    local default_version="28.2.2"
    echo ""
    log_info "Docker版本选择："
    echo "  - 输入具体版本号 (如: 28.2.2, 27.3.1)"
    echo "  - 输入 'latest' 获取最新版本"
    echo "  - 直接回车使用默认版本: ${default_version}"
    read -rp "请输入Docker版本 [${default_version}]: " user_version

    if [[ -z "${user_version}" ]]; then
      docker_version="${default_version}"
      log_info "使用默认版本: ${docker_version}"
    elif [[ "${user_version,,}" == "latest" ]]; then
      log_info "获取最新Docker版本..."

      if ! command -v jq &>/dev/null; then
        log_warning "jq未安装，尝试安装jq..."
        if ! ${SUDO_CMD} apt update && ${SUDO_CMD} apt install -y jq; then
          log_error "jq安装失败，无法获取最新版本，使用默认版本: ${default_version}"
          docker_version="${default_version}"
        fi
      fi

      if command -v jq &>/dev/null; then
        local api_url="https://endoflife.date/api/docker-engine.json"
        log_info "从 ${api_url} 获取最新版本信息..."

        local latest_version
        if latest_version="$(curl -s "${api_url}" 2>/dev/null | jq -r '.[0].latest' 2>/dev/null)" && [[ -n "${latest_version}" && "${latest_version}" != "null" ]]; then
          docker_version="${latest_version}"
          log_success "获取到最新版本: ${docker_version}"
        else
          log_warning "所有获取最新版本的方法都失败，使用默认版本: ${default_version}"
          docker_version="${default_version}"
        fi
      else
        log_warning "jq不可用，使用默认版本: ${default_version}"
        docker_version="${default_version}"
      fi
    else
      docker_version="${user_version}"
      log_info "使用用户指定版本: ${docker_version}"
    fi
  fi

  # 验证版本号格式
  if [[ ! "${docker_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    log_warning "版本号格式可能不正确: ${docker_version}，但继续尝试下载..."
  fi

  # 构建缓存文件路径和下载URL
  cache_file="/tmp/docker-${docker_version}.tgz"
  url="https://download.docker.com/linux/static/stable/${arch}/docker-${docker_version}.tgz"

  # 创建Docker目录
  ${SUDO_CMD} mkdir -p /usr/local/bin /etc/docker /opt/docker/down

  # 检查缓存文件
  local use_cache=false
  if [[ -f "${cache_file}" ]]; then
    log_info "发现缓存文件: ${cache_file}"

    if tar -tzf "${cache_file}" >/dev/null 2>&1; then
      local cache_size
      cache_size=$(stat -c%s "${cache_file}" 2>/dev/null || echo "0")
      if [[ "${cache_size}" -gt 1048576 ]]; then
        log_success "缓存文件验证通过，使用缓存文件"
        use_cache=true
      else
        log_warning "缓存文件太小 (${cache_size} bytes)，可能不完整，将重新下载"
        rm -f "${cache_file}" || true
      fi
    else
      log_warning "缓存文件损坏，将重新下载"
      rm -f "${cache_file}" || true
    fi
  else
    log_info "未找到缓存文件: ${cache_file}"
  fi

  # 检查/opt/docker/down中是否有缓存
  local opt_cache_file="/opt/docker/down/docker-${docker_version}.tgz"
  if [[ -f "${opt_cache_file}" ]]; then
    log_info "发现/opt/docker/down中的缓存文件"
    use_cache=true
    cache_file="${opt_cache_file}"
  fi

  # 下载或使用缓存
  tgzdir="$(mktemp -d)"
  if [[ "${use_cache}" == "true" ]]; then
    log_info "使用缓存文件: ${cache_file}"
    cp "${cache_file}" "${tgzdir}/docker.tgz"
  else
    log_info "从 ${url} 下载Docker..."

    if ! curl -fsSL "${url}" -o "${tgzdir}/docker.tgz"; then
      log_error "下载Docker失败！"
      log_error "可能的原因："
      log_error "  1. 版本号不存在: ${docker_version}"
      log_error "  2. 架构不支持: ${arch}"
      log_error "  3. 网络连接问题"
      log_info "请访问 https://download.docker.com/linux/static/stable/${arch}/ 查看可用版本"
      rm -rf "${tgzdir}"
      return 1
    fi

    # 下载成功后保存到缓存
    log_info "保存到缓存: ${opt_cache_file}"
    ${SUDO_CMD} cp "${tgzdir}/docker.tgz" "${opt_cache_file}" || log_warning "缓存保存失败，但不影响安装"
    cp "${tgzdir}/docker.tgz" "${cache_file}" || log_warning "临时缓存保存失败，但不影响安装"
  fi

  log_info "解压Docker二进制文件..."
  if ! tar xzf "${tgzdir}/docker.tgz" -C "${tgzdir}"; then
    log_error "解压Docker失败，可能下载文件损坏"
    if [[ "${use_cache}" == "true" ]]; then
      log_info "删除损坏的缓存文件: ${cache_file}"
      rm -f "${cache_file}" || true
    fi
    rm -rf "${tgzdir}"
    return 1
  fi

  log_info "安装Docker二进制文件到 /usr/local/bin/..."
  ${SUDO_CMD} cp "${tgzdir}"/docker/* /usr/local/bin/
  ${SUDO_CMD} ln -sf /usr/local/bin/docker /bin/docker
  rm -rf "${tgzdir}"

  # 验证安装
  if ! command -v docker &>/dev/null; then
    log_error "Docker安装失败，二进制文件未正确复制"
    return 1
  fi

  log_success "Docker ${docker_version} 二进制文件安装完成"

  # 创建docker组并添加用户
  if command -v groupadd &>/dev/null; then
    ${SUDO_CMD} groupadd -f docker
  else
    ${SUDO_CMD} /usr/sbin/groupadd -f docker
  fi

  if command -v usermod &>/dev/null; then
    ${SUDO_CMD} usermod -aG docker "${TARGET_USER}"
  else
    ${SUDO_CMD} /usr/sbin/usermod -aG docker "${TARGET_USER}"
  fi

  # 安装并配置containerd
  log_info "安装和配置containerd..."
  local containerd_installed=false

  if ${SUDO_CMD} apt install -y containerd.io 2>/dev/null; then
    containerd_installed=true
    log_success "安装containerd.io成功"
  elif ${SUDO_CMD} apt install -y containerd 2>/dev/null; then
    containerd_installed=true
    log_success "安装containerd成功"
  else
    log_warning "通过apt安装containerd失败，尝试手动安装..."
    local containerd_version="1.7.24"
    local containerd_url="https://github.com/containerd/containerd/releases/download/v${containerd_version}/containerd-${containerd_version}-linux-${arch}.tar.gz"
    local containerd_cache="/tmp/containerd-${containerd_version}-linux-${arch}.tar.gz"

    if [[ ! -f "${containerd_cache}" ]]; then
      log_info "下载containerd ${containerd_version}..."
      if curl -fsSL "$(add_github_proxy "${containerd_url}")" -o "${containerd_cache}"; then
        log_success "containerd下载完成"
      else
        log_error "containerd下载失败"
        return 1
      fi
    else
      log_info "使用缓存的containerd: ${containerd_cache}"
    fi

    log_info "安装containerd..."
    local temp_dir="$(mktemp -d)"
    if tar -xzf "${containerd_cache}" -C "${temp_dir}"; then
      ${SUDO_CMD} cp "${temp_dir}"/bin/* /usr/local/bin/
      rm -rf "${temp_dir}"
      containerd_installed=true
      log_success "containerd手动安装完成"
    else
      log_error "containerd解压失败"
      rm -rf "${temp_dir}"
      return 1
    fi
  fi

  if [[ "${containerd_installed}" == "true" ]]; then
    ${SUDO_CMD} mkdir -p /etc/containerd

    if command -v containerd &>/dev/null; then
      ${SUDO_CMD} containerd config default | ${SUDO_CMD} tee /etc/containerd/config.toml >/dev/null
      log_info "containerd默认配置已生成"
    fi

    # 创建containerd systemd服务文件
    ${SUDO_CMD} tee /etc/systemd/system/containerd.service >/dev/null <<'EOF'
[Unit]
Description=containerd container runtime
Documentation=https://containerd.io
After=network.target local-fs.target

[Service]
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/local/bin/containerd
Type=notify
Delegate=yes
KillMode=process
Restart=always
RestartSec=5
LimitNPROC=infinity
LimitCORE=infinity
LimitNOFILE=infinity
TasksMax=infinity
OOMScoreAdjust=-999

[Install]
WantedBy=multi-user.target
EOF
    log_success "containerd服务配置完成"
  fi

  # 配置Docker daemon.json（根据地区配置镜像源）
  log_info "配置Docker daemon.json..."
  ${SUDO_CMD} mkdir -p /etc/docker

  local registry_mirrors
  local effective_mirror_setting=$(get_docker_registry_mirrors)
  
  if [[ "${effective_mirror_setting}" == "CN" ]]; then
    registry_mirrors='"https://docker.m.daocloud.io",
        "https://docker.1ms.run",
        "https://ccr.ccs.tencentyun.com",
        "https://hub.xdark.top",
        "https://hub.fast360.xyz",
        "https://docker-0.unsee.tech",
        "https://docker.xuanyuan.me",
        "https://docker.tbedu.top",
        "https://docker.hlmirror.com",
        "https://doublezonline.cloud",
        "https://docker.melikeme.cn",
        "https://image.cloudlayer.icu",
        "https://dislabaiot.xyz",
        "https://freeno.xyz",
        "https://docker.kejilion.pro",
        "https://docker.rainbond.cc"'
    log_info "配置中国镜像加速器"
  else
    registry_mirrors=''
    log_info "使用官方Docker Hub"
  fi

  ${SUDO_CMD} tee /etc/docker/daemon.json >/dev/null <<EOF
{
    "data-root": "/var/lib/docker",
    "log-driver": "json-file",
    "log-level": "warn",
    "log-opts": {
        "max-file": "3",
        "max-size": "10m"
    },
    "max-concurrent-downloads": 10,
    "max-concurrent-uploads": 10,$(if [[ -n "${registry_mirrors}" ]]; then echo "
    \"registry-mirrors\": [
        ${registry_mirrors}
    ],"; fi)
    "exec-opts": ["native.cgroupdriver=systemd"],
    "live-restore": true,
    "storage-driver": "overlay2"
}
EOF
  log_success "Docker daemon.json配置完成"

  # 创建优化的docker systemd服务文件
  log_info "配置Docker systemd服务..."
  ${SUDO_CMD} tee /etc/systemd/system/docker.service >/dev/null <<'EOF'
[Unit]
Description=Docker Application Container Engine
Documentation=http://docs.docker.io
After=network-online.target containerd.service
Wants=network-online.target
Requires=containerd.service

[Service]
OOMScoreAdjust=-1000
Environment="PATH=/usr/local/bin:/bin:/sbin:/usr/bin:/usr/sbin"
ExecStart=/usr/local/bin/dockerd
ExecStartPost=/sbin/iptables -I FORWARD -s 0.0.0.0/0 -j ACCEPT
ExecReload=/bin/kill -s HUP $MAINPID
Type=notify
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
Delegate=yes
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

  ${SUDO_CMD} tee /etc/systemd/system/docker.socket >/dev/null <<'EOF'
[Unit]
Description=Docker Socket for the API
PartOf=docker.service

[Socket]
ListenStream=/var/run/docker.sock
SocketMode=0660
SocketUser=root
SocketGroup=docker

[Install]
WantedBy=sockets.target
EOF

  # 启动服务
  if command -v systemctl &>/dev/null; then
    ${SUDO_CMD} systemctl daemon-reload
    ${SUDO_CMD} systemctl enable containerd.service
    ${SUDO_CMD} systemctl enable docker.service docker.socket

    # 启动containerd
    if ${SUDO_CMD} systemctl start containerd.service; then
      log_success "containerd服务启动成功"
    else
      log_error "containerd服务启动失败，请检查日志: sudo journalctl -u containerd.service"
      return 1
    fi

    sleep 3

    # 启动docker
    if ${SUDO_CMD} systemctl start docker.service; then
      log_success "Docker服务启动成功"

      sleep 2
      if ${SUDO_CMD} systemctl is-active --quiet docker.service; then
        log_success "Docker服务运行正常"

        local installed_version
        installed_version="$(docker --version 2>/dev/null || echo "无法获取版本信息")"
        log_info "已安装版本: ${installed_version}"

        if docker info >/dev/null 2>&1; then
          log_success "Docker运行测试通过"

          log_info "测试Docker镜像拉取功能..."
          if timeout 30 docker pull hello-world:latest >/dev/null 2>&1; then
            log_success "Docker镜像拉取测试成功"
            docker rmi hello-world:latest >/dev/null 2>&1 || true
          else
            log_warning "Docker镜像拉取测试失败，但Docker已正常安装"
          fi
        else
          log_warning "Docker已安装但可能无法正常运行，请检查配置"
        fi
      else
        log_warning "Docker服务启动后状态异常，请检查日志: sudo journalctl -u docker.service"
      fi
    else
      log_error "Docker服务启动失败，请检查日志: sudo journalctl -u docker.service"
      return 1
    fi
  else
    ${SUDO_CMD} /bin/systemctl daemon-reload
    ${SUDO_CMD} /bin/systemctl enable containerd.service
    ${SUDO_CMD} /bin/systemctl enable docker.service docker.socket

    if ${SUDO_CMD} /bin/systemctl start containerd.service; then
      log_success "containerd服务启动成功"
    else
      log_error "containerd服务启动失败"
      return 1
    fi

    sleep 3

    if ${SUDO_CMD} /bin/systemctl start docker.service; then
      log_success "Docker服务启动成功"
      sleep 2

      local installed_version
      installed_version="$(docker --version 2>/dev/null || echo "无法获取版本信息")"
      log_info "已安装版本: ${installed_version}"
    else
      log_error "Docker服务启动失败"
      return 1
    fi
  fi

  log_success "Docker ${docker_version} 安装完成！"
  log_warning "用户 ${TARGET_USER} 需要重新登录或运行 'newgrp docker' 以使docker组权限生效。"

  if [[ -f "${cache_file}" ]]; then
    log_info "Docker安装包已缓存至: ${cache_file}"
  fi

  local mirror_count
  if [[ "${effective_mirror_setting}" == "CN" ]]; then
    mirror_count="16"
  else
    mirror_count="0"
  fi
  log_info "Docker镜像配置完成，包含${mirror_count}个镜像源"

  mark_completed "docker"
}

# ---- 步骤 11：安装 Docker Compose (优化版本，与Docker逻辑一致) ----
install_docker_compose() {
  skip_if_completed "docker_compose" && return
  log_step "安装Docker Compose"
  
  log_info "安装 Docker Compose…"

  # 检查是否已安装
  if command -v docker-compose &>/dev/null; then
    local current_version
    current_version="$(docker-compose --version 2>/dev/null | sed -n 's/.*version \([^,]*\).*/\1/p' || echo "unknown")"
    log_warning "docker-compose 已存在，版本: ${current_version}，跳过安装。"
    mark_completed "docker_compose"
    return
  fi

  # 检查新版 docker compose 插件
  if docker compose version &>/dev/null; then
    local current_version
    current_version="$(docker compose version --short 2>/dev/null || echo "unknown")"
    log_warning "Docker Compose (插件版本) 已存在，版本: ${current_version}，跳过安装。"
    mark_completed "docker_compose"
    return
  fi

  # 确定系统架构
  local arch
  arch="$(uname -m)"
  case "${arch}" in
    x86_64)   arch="x86_64" ;;
    aarch64)  arch="aarch64" ;;
    armv7l)   arch="armv7" ;;
    armv6l)   arch="armv6" ;;
    ppc64le)  arch="ppc64le" ;;
    s390x)    arch="s390x" ;;
    riscv64)  arch="riscv64" ;;
    *)        log_error "不支持的架构：${arch}"; return 1 ;;
  esac

  log_info "检测到系统架构: ${arch}"

  # 获取Docker Compose版本号（与Docker安装逻辑一致）
  local compose_version
  if [[ -n "${DOCKER_COMPOSE_VERSION:-}" ]]; then
    compose_version="${DOCKER_COMPOSE_VERSION}"
    log_info "使用环境变量指定的Docker Compose版本: ${compose_version}"
  else
    local default_version="v2.36.2"
    echo ""
    log_info "Docker Compose版本选择："
    echo "  - 输入具体版本号 (如: v2.36.2, v2.35.1)"
    echo "  - 输入 'latest' 获取最新版本"
    echo "  - 直接回车使用默认版本: ${default_version}"
    read -rp "请输入Docker Compose版本 [${default_version}]: " user_version

    if [[ -z "${user_version}" ]]; then
      compose_version="${default_version}"
      log_info "使用默认版本: ${compose_version}"
    elif [[ "${user_version,,}" == "latest" ]]; then
      log_info "获取最新Docker Compose版本..."

      # 确保jq已安装
      if ! command -v jq &>/dev/null; then
        log_warning "jq未安装，尝试安装jq..."
        if ! ${SUDO_CMD} apt update && ${SUDO_CMD} apt install -y jq; then
          log_error "jq安装失败，无法获取最新版本，使用默认版本: ${default_version}"
          compose_version="${default_version}"
        fi
      fi

      if command -v jq &>/dev/null; then
        local api_url
        api_url="$(add_github_proxy 'https://api.github.com/repos/docker/compose/releases/latest')"
        log_info "从 ${api_url} 获取最新版本信息..."

        local latest_version
        if latest_version="$(curl -fsSL "${api_url}" 2>/dev/null | jq -r '.tag_name' 2>/dev/null)" && [[ -n "${latest_version}" && "${latest_version}" != "null" ]]; then
          compose_version="${latest_version}"
          log_success "获取到最新版本: ${compose_version}"
        else
          log_warning "获取最新版本失败，使用默认版本: ${default_version}"
          compose_version="${default_version}"
        fi
      else
        log_warning "jq不可用，使用默认版本: ${default_version}"
        compose_version="${default_version}"
      fi
    else
      compose_version="${user_version}"
      log_info "使用用户指定版本: ${compose_version}"
    fi
  fi

  # 确保版本号以v开头
  if [[ ! "${compose_version}" =~ ^v ]]; then
    compose_version="v${compose_version}"
  fi

  # 验证版本号格式
  if [[ ! "${compose_version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    log_warning "版本号格式可能不正确: ${compose_version}，但继续尝试下载..."
  fi

  # 构建缓存文件路径和下载URL
  local cache_file="/tmp/docker-compose-${compose_version}-linux-${arch}"
  local download_url
  download_url="$(add_github_proxy "https://github.com/docker/compose/releases/download/${compose_version}/docker-compose-linux-${arch}")"

  log_info "下载URL: ${download_url}"

  # 检查缓存文件
  local use_cache=false
  if [[ -f "${cache_file}" ]]; then
    log_info "发现缓存文件: ${cache_file}"

    local cache_size
    cache_size=$(stat -c%s "${cache_file}" 2>/dev/null || echo "0")
    if [[ "${cache_size}" -gt 1048576 ]]; then  # 大于1MB
      log_success "缓存文件验证通过，使用缓存文件"
      use_cache=true
    else
      log_warning "缓存文件太小 (${cache_size} bytes)，可能不完整，将重新下载"
      rm -f "${cache_file}" || true
    fi
  else
    log_info "未找到缓存文件: ${cache_file}"
  fi

  # 下载或使用缓存
  local temp_file
  if [[ "${use_cache}" == "true" ]]; then
    temp_file="${cache_file}"
  else
    temp_file="$(mktemp --tmpdir docker-compose.XXXXXX)"

    log_info "下载Docker Compose二进制文件..."
    if ! curl -fsSL "${download_url}" -o "${temp_file}"; then
      log_error "下载Docker Compose失败！"
      log_error "可能的原因："
      log_error "  1. 版本号不存在: ${compose_version}"
      log_error "  2. 架构不支持: ${arch}"
      log_error "  3. 网络连接问题"
      log_info "请访问 https://github.com/docker/compose/releases/tag/${compose_version} 查看可用的架构"
      rm -f "${temp_file}"
      return 1
    fi

    # 验证下载的文件
    if [[ ! -s "${temp_file}" ]]; then
      log_error "下载的文件为空"
      rm -f "${temp_file}"
      return 1
    fi

    local file_size
    file_size="$(stat -c%s "${temp_file}" 2>/dev/null || echo "0")"
    if [[ "${file_size}" -lt 1048576 ]]; then  # 小于1MB可能有问题
      log_warning "下载的文件大小异常 (${file_size} bytes)，但继续安装..."
    fi

    # 保存到缓存
    log_info "保存到缓存: ${cache_file}"
    cp "${temp_file}" "${cache_file}" || log_warning "缓存保存失败，但不影响安装"
  fi

  # 安装文件
  log_info "安装Docker Compose到 /usr/local/bin/docker-compose..."

  if [[ "${use_cache}" == "true" ]]; then
    ${SUDO_CMD} cp "${temp_file}" /usr/local/bin/docker-compose
  else
    ${SUDO_CMD} mv "${temp_file}" /usr/local/bin/docker-compose
  fi

  ${SUDO_CMD} chmod +x /usr/local/bin/docker-compose

  # 创建符号链接
  ${SUDO_CMD} ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose

  # 验证安装
  if ! command -v docker-compose &>/dev/null; then
    log_error "Docker Compose安装失败，命令不可用"
    return 1
  fi

  # 获取安装后的版本
  local installed_version
  installed_version="$(docker-compose --version 2>/dev/null || echo "无法获取版本信息")"
  log_success "Docker Compose ${compose_version} 安装完成！"
  log_info "安装版本: ${installed_version}"

  # 测试基本功能
  if docker-compose version &>/dev/null; then
    log_success "Docker Compose功能测试通过"
  else
    log_warning "Docker Compose功能测试失败，但已成功安装"
  fi

  # 显示缓存信息
  if [[ -f "${cache_file}" ]]; then
    log_info "Docker Compose安装包已缓存至: ${cache_file}"
  fi

  mark_completed "docker_compose"
}

# ---- 步骤 12：安装额外开发工具 (可选) ----
install_extra_tools() {
  if [[ "${INSTALL_EXTRA_TOOLS}" != "true" ]]; then
    log_info "跳过额外开发工具安装"
    return
  fi

  skip_if_completed "extra_tools" && return
  log_step "安装额外开发工具"
  
  log_info "安装额外开发工具…"

  # 安装 Node.js
  if ! command -v node &>/dev/null; then
    log_info "安装 Node.js LTS..."
    local node_script_url="https://deb.nodesource.com/setup_lts.x"
    local node_script="$(mktemp --tmpdir nodesource_setup.XXXXXX.sh)"
    download_and_process_script "${node_script_url}" "${node_script}" "false"

    # 修复sudo -E的问题
    if [[ -n "${SUDO_CMD}" ]]; then
      ${SUDO_CMD} -E bash "${node_script}"
    else
      bash "${node_script}"
    fi

    rm -f "${node_script}"
    ${SUDO_CMD} apt install -y nodejs
    log_success "Node.js安装完成"
  else
    log_info "Node.js已安装，跳过"
  fi

  # 安装基础开发工具
  log_info "安装基础开发工具..."
  ${SUDO_CMD} apt install -y \
    python3-pip default-jdk golang-go ruby-full php-cli php-sqlite3 sqlite3 \
    postgresql-client redis-tools jq yq

  # 尝试安装MySQL客户端（处理不同的包名）
  log_info "安装MySQL客户端..."
  if ${SUDO_CMD} apt install -y default-mysql-client 2>/dev/null; then
    log_success "MySQL客户端 (default-mysql-client) 安装成功"
  elif ${SUDO_CMD} apt install -y mysql-client-core-8.0 2>/dev/null; then
    log_success "MySQL客户端 (mysql-client-core-8.0) 安装成功"
  elif ${SUDO_CMD} apt install -y mysql-client-8.0 2>/dev/null; then
    log_success "MySQL客户端 (mysql-client-8.0) 安装成功"
  elif ${SUDO_CMD} apt install -y mariadb-client 2>/dev/null; then
    log_success "MySQL客户端 (mariadb-client) 安装成功"
  else
    log_warning "MySQL客户端安装失败，请手动安装"
  fi

  # 安装VSCode
  if command -v snap &>/dev/null && ! command -v code &>/dev/null; then
    log_info "通过 Snap 安装 VSCode (code)..."
    ${SUDO_CMD} snap install code --classic || log_warning "VSCode (snap) 安装失败。"
  elif ! command -v code &>/dev/null; then
    log_info "尝试通过 apt 安装 VSCode (code)..."
    ${SUDO_CMD} apt-get install -y wget gpg
    wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
    ${SUDO_CMD} install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg
    ${SUDO_CMD} sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list'
    rm -f packages.microsoft.gpg
    ${SUDO_CMD} apt update
    ${SUDO_CMD} apt install -y code || log_warning "VSCode (apt) 安装失败. 可以尝试手动安装 code-oss."
  else
    log_info "VSCode已安装，跳过"
  fi

  log_success "额外工具安装完成。"
  mark_completed "extra_tools"
}

# ---- 步骤 13：配置 Git ----
configure_git() {
  skip_if_completed "git" && return
  log_step "配置Git"
  
  log_info "配置 Git…"

  local current_name current_email git_name git_email
  current_name="$(run_as_user "git config --global user.name" 2>/dev/null || true)"
  current_email="$(run_as_user "git config --global user.email" 2>/dev/null || true)"

  if [[ -z "${current_name}" ]]; then
    read -rp "请输入 Git 用户名 (例如 Your Name, 回车跳过): " git_name
    [[ -n "${git_name}" ]] && run_as_user "git config --global user.name '${git_name}'"
  fi
  if [[ -z "${current_email}" ]]; then
    read -rp "请输入 Git 邮箱 (例如 your.email@example.com, 回车跳过): " git_email
    [[ -n "${git_email}" ]] && run_as_user "git config --global user.email '${git_email}'"
  fi

  run_as_user "git config --global init.defaultBranch main"
  run_as_user "git config --global pull.rebase false"
  run_as_user "git config --global core.editor vim"
  log_success "Git 配置完成。"
  mark_completed "git"
}

# ---- 步骤 14：最终设置 ----
final_setup() {
  skip_if_completed "final_setup" && return
  log_step "最终设置"
  
  log_info "做最后的目录和别名设置…"
  create_user_dir "${TARGET_HOME}/Projects"
  create_user_dir "${TARGET_HOME}/Scripts"
  create_user_dir "${TARGET_HOME}/Downloads"

  local zshrc_file="${TARGET_HOME}/.zshrc"
  if [[ ! -f "${zshrc_file}" ]]; then
    run_as_user "touch '${zshrc_file}'"
  fi

  if ! run_as_user "grep -q '# 自定义别名' '${zshrc_file}'" 2>/dev/null; then
    local aliases_content
    aliases_content=$(cat <<'EOF'

# 自定义别名
alias ll='ls -alFh'
alias la='ls -Ah'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'
alias h='history'; alias c='clear'
alias t='tmux new-session -A -s main'; alias ta='tmux attach -t'; alias tl='tmux ls'
alias v='vim'; alias g='git'
alias d='docker'; alias dc='docker compose'; alias k='kubectl'
alias proj='cd ~/Projects'
alias scripts='cd ~/Scripts'
alias dl='cd ~/Downloads'

# Docker 别名
alias dps='docker ps -a'; alias di='docker images'
alias drm='docker rm'; alias drmi='docker rmi'
alias dlogs='docker logs -f'
alias dexec='docker exec -it'
alias dstop='docker stop'; alias dstart='docker start'

# Git 别名
alias gs='git status -sb'; alias ga='git add'; gaa='git add .'; alias gc='git commit -m'; alias gca='git commit -am'
alias gp='git push'; alias gpl='git pull'; alias gpf='git push --force-with-lease'
alias gb='git branch'; alias gco='git checkout'; alias gcb='git checkout -b'
alias glog="git log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit"
alias gdiff='git diff'
alias gignore='echo .DS_Store >> .gitignore && echo Thumbs.db >> .gitignore && echo node_modules/ >> .gitignore && echo .vscode/ >> .gitignore && echo __pycache__/ >> .gitignore && echo "*.pyc" >> .gitignore'

# System update alias
alias update='sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y'

# Vim相关别名
alias vi='vim'
alias vimdiff='vim -d'
EOF
)
    run_as_user "echo \"${aliases_content}\" >> '${zshrc_file}'"
  fi
  log_success "最终设置完成。"
  mark_completed "final_setup"
}

# ---- 显示完成摘要 ----
show_summary() {
  log_success "=== 开发环境配置完成 ==="
  
  local proxy_info=""
  local mirror_info=""
  local effective_mirror_setting=$(get_docker_registry_mirrors)
  
  if [[ "${IN_CHINA}" == "true" ]]; then
    proxy_info="${GITHUB_PROXY:-https://ghfast.top}"
    if [[ "${effective_mirror_setting}" == "CN" ]]; then
      mirror_info="中国镜像源（阿里云APT源 + 16个Docker镜像源）"
    else
      mirror_info="中国镜像源（阿里云APT源）+ 官方Docker Hub"
    fi
  else
    proxy_info="(无，非中国大陆地区)"
    mirror_info="官方源"
  fi
  
  cat <<EOF
地区配置: ${IN_CHINA} $(if [[ "${IN_CHINA}" == "auto" ]]; then echo "(自动检测)"; fi)
目标用户: ${TARGET_USER}
GitHub代理: ${proxy_info}
镜像源配置: ${mirror_info}

已安装/配置：
  • SSH服务 (允许root登录，密码认证)
  • SSH密钥对 (已配置免密登录到localhost)
  • iptables (Docker依赖)
$(if [[ "${IN_CHINA}" == "true" ]]; then
  echo "  • 阿里云APT镜像源 (中国大陆优化)"
else
  echo "  • 官方APT源 (保持默认配置)"
fi)
  • zsh + Oh My Zsh + Powerlevel10k
  • vim (Catppuccin 浅色主题 - catppuccin_latte)
  • tmux (Catppuccin Latte 浅色主题, 前缀+I 安装插件)
  • Miniconda (conda init zsh/bash 已执行)
  • Docker & Docker Compose (优化版本，一致的安装逻辑)
    - Docker: 支持本地缓存和/opt/docker/down缓存
    - Docker Compose: 支持本地缓存和版本选择
$(if [[ "${effective_mirror_setting}" == "CN" ]]; then
    echo "    - 配置了16个Docker镜像加速器 (中国大陆优化)"
else
    echo "    - 使用官方Docker Hub (非中国大陆地区)"
fi)
    - containerd 已安装并配置
    - 优化的systemd服务配置
    - iptables前向规则自动配置
    - 支持多架构: x86_64, aarch64, armv7, armv6, ppc64le, s390x, riscv64
$(if [[ "${INSTALL_EXTRA_TOOLS}" == "true" ]]; then
  echo "  • Node.js (LTS), Python3-pip, JDK, Go, Ruby, PHP, DB clients"
  echo "  • Visual Studio Code"
else
  echo "  • 额外开发工具: 已跳过安装"
fi)
  • Git (基本配置)
  • 常用目录和 zsh 别名

Vim配置亮点：
  • 主题: Catppuccin Latte (浅色配色方案)
  • 启用真彩色支持 (termguicolors)
  • 丰富的快捷键配置
  • 智能缩进和语法高亮
  • 配置文件: ${TARGET_HOME}/.vimrc

tmux配置亮点：
  • 主题: Catppuccin Latte (浅色)
  • 鼠标支持和历史记录优化
  • 自定义快捷键绑定

地区适配特性：
  • 自动检测地区 (时区、语言、IP等)
  • 中国大陆: 启用阿里云源、GitHub代理、Docker镜像加速
  • 其他地区: 使用官方源，无代理，保持原生体验
  • 支持手动覆盖: IN_CHINA=true/false

重要提示：
  1. 用户 ${TARGET_USER} 需要重新登录以使以下更改完全生效：
     - zsh 作为默认 shell
     - Docker 用户组权限
     - 新的 PATH 环境变量
  2. Vim & tmux 主题统一：
     - 都使用 Catppuccin Latte 浅色主题
     - 在终端中使用体验一致
  3. Docker & Docker Compose配置：
     - 版本检查：已安装的Docker版本不能低于1.13.x
     - 默认版本：Docker ${DOCKER_VERSION}, Docker Compose ${DOCKER_COMPOSE_VERSION}
     - 缓存机制：安装包会缓存在 /tmp/ 目录
     - 版本选择：支持环境变量或交互式输入
$(if [[ "${effective_mirror_setting}" == "CN" ]]; then
    echo "     - 镜像加速：支持16个国内镜像源（中国大陆地区）"
else
    echo "     - 镜像配置：使用官方Docker Hub（非中国大陆地区）"
fi)
  4. 环境变量支持：
     - IN_CHINA: 地区配置 (auto/true/false, 默认: auto)
     - DOCKER_VERSION: 指定Docker版本 (默认: 28.2.2)
     - DOCKER_COMPOSE_VERSION: 指定Docker Compose版本 (默认: v2.36.2)
$(if [[ "${IN_CHINA}" == "true" ]]; then
    echo "     - GITHUB_PROXY: GitHub代理地址 (默认: https://ghfast.top)"
else
    echo "     - GITHUB_PROXY: GitHub代理地址 (当前禁用，非中国大陆)"
fi)
     - REGISTRY_MIRROR: Docker镜像源 (auto/CN/NONE, 默认: auto)
  5. 验证安装：
     - 'docker --version' 和 'docker info'
     - 'docker-compose --version' 或 'docker compose version'
     - 'vim --version' 查看Vim配置
     - 其他工具版本检查
  6. SSH密钥已配置，可测试 'ssh ${TARGET_USER}@127.0.0.1'
  7. 状态管理：删除 $(get_status_file) 可重置安装状态

缓存位置：
  - Docker: /tmp/docker-${DOCKER_VERSION}.tgz, /opt/docker/down/docker-${DOCKER_VERSION}.tgz
  - Docker Compose: /tmp/docker-compose-${DOCKER_COMPOSE_VERSION}-linux-\${arch}

配置文件：
  - Vim: ${TARGET_HOME}/.vimrc (Catppuccin Latte 主题)
  - tmux: ${TARGET_HOME}/.tmux.conf (Catppuccin Latte 主题)
  - Docker: /etc/docker/daemon.json
  - Docker Compose: 独立二进制文件安装
$(if [[ "${IN_CHINA}" == "true" ]]; then
    echo "  - APT源: /etc/apt/sources.list (阿里云镜像)"
else
    echo "  - APT源: /etc/apt/sources.list (保持系统默认)"
fi)
EOF
}

# ---- 主流程 ----
main() {
  case "${1:-}" in
    --clean)
      init_user_info
      if [[ -f "$(get_status_file)" ]]; then
        rm -f "$(get_status_file)" && log_info "状态文件已清理: $(get_status_file)"
      else
        log_info "状态文件不存在: $(get_status_file)"
      fi
      exit 0 ;;
    --status)
      init_user_info
      if [[ -f "$(get_status_file)" ]]; then
        log_info "已完成的步骤 ($(get_status_file)):"
        cat "$(get_status_file)"
      else
        log_info "尚无已完成步骤记录 ($(get_status_file))。"
      fi
      exit 0 ;;
    -h|--help)
      echo "用法: $0 [选项]"
      echo "  --clean   清理状态文件"
      echo "  --status  显示已完成步骤"
      echo "  --help    显示此帮助信息"
      echo ""
      echo "环境变量:"
      echo "  IN_CHINA               地区配置 (auto/true/false, 默认: auto)"
      echo "                         - auto: 自动检测地区"
      echo "                         - true: 强制启用中国大陆配置"
      echo "                         - false: 强制禁用中国大陆配置"
      echo "  GITHUB_PROXY           GitHub代理前缀 (仅中国大陆时启用, 默认: https://ghfast.top)"
      echo "  DOCKER_VERSION         Docker版本号 (默认: 28.2.2)"
      echo "  DOCKER_COMPOSE_VERSION Docker Compose版本号 (默认: v2.36.2)"
      echo "  REGISTRY_MIRROR        Docker镜像源 (auto/CN/NONE, 默认: auto)"
      echo "                         - auto: 根据地区自动配置"
      echo "                         - CN: 强制使用中国镜像源"
      echo "                         - NONE: 使用官方Docker Hub"
      echo ""
      echo "地区适配特性 (新增):"
      echo "  ✓ 自动地区检测 - 基于时区、语言环境、IP地址等多种方式"
      echo "  ✓ 智能镜像配置 - 中国大陆启用阿里云APT源和Docker镜像加速"
      echo "  ✓ GitHub代理支持 - 仅在中国大陆时启用GitHub访问加速"
      echo "  ✓ 全球化友好 - 非中国地区保持原生官方源配置"
      echo ""
      echo "现有特性 (优化版):"
      echo "  ✓ 额外工具可选安装 - 脚本运行时可选择是否安装开发工具"
      echo "  ✓ Vim Catppuccin浅色主题 - 使用catppuccin_latte浅色配色"
      echo "  ✓ tmux Catppuccin浅色主题 - 与vim主题保持一致"
      echo "  ✓ 增强的用户交互 - 彩色日志输出和步骤提示"
      echo "  ✓ 优化的错误处理和状态管理"
      echo ""
      echo "Docker & Docker Compose增强:"
      echo "  - 统一的版本选择逻辑 (默认版本/环境变量/交互选择/latest)"
      echo "  - 智能缓存机制，避免重复下载"
      echo "  - 支持多架构: x86_64, aarch64, armv7, armv6, ppc64le, s390x, riscv64"
      echo "  - 完整的错误处理和版本验证"
      echo "  - GitHub代理支持加速下载（仅中国大陆）"
      echo ""
      echo "使用示例:"
      echo "  $0                                          # 自动检测地区并配置"
      echo "  IN_CHINA=true $0                           # 强制启用中国大陆配置"
      echo "  IN_CHINA=false $0                          # 强制使用国际配置"
      echo "  IN_CHINA=true DOCKER_VERSION=27.3.1 $0    # 中国配置+指定Docker版本"
      echo "  REGISTRY_MIRROR=NONE $0                    # 禁用Docker镜像加速"
      echo "  GITHUB_PROXY='' IN_CHINA=true $0           # 中国配置但禁用GitHub代理"
      exit 0 ;;
  esac

  echo ""
  log_success "=== Debian/Ubuntu 开发环境配置脚本 (地区适配版) ==="
  echo ""
  
  # 首先检测地区
  detect_china_region
  
  log_info "开始配置开发环境..."
  log_info "地区配置: ${IN_CHINA}"
  log_info "GitHub代理: $(get_github_proxy || echo "(无)")"
  log_info "Docker镜像源: $(get_docker_registry_mirrors)"
  log_info "Docker版本: ${DOCKER_VERSION}"
  log_info "Docker Compose版本: ${DOCKER_COMPOSE_VERSION}"

  init_user_info
  check_system

  if [[ -f "$(get_status_file)" ]]; then
    log_info "检测到之前的配置记录，将跳过已完成步骤："
    cat "$(get_status_file)"
    echo
  fi

  echo ""
  read -rp "是否继续为用户 ${TARGET_USER} (HOME: ${TARGET_HOME}) 配置开发环境？(y/N): " yn
  [[ "${yn,,}" == "y" ]] || { log_info "操作已取消。"; exit 0; }

  # 配置安装选项
  configure_installation_options

  echo ""
  log_success "开始执行配置步骤..."
  echo ""

  fix_path
  setup_sudo
  setup_ssh
  setup_ssh_keys
  setup_aliyun_mirror
  update_system
  install_basic_tools
  install_zsh
  install_oh_my_zsh
  install_powerlevel10k
  configure_vim
  install_tmux
  configure_tmux
  install_miniconda
  install_docker
  install_docker_compose
  install_extra_tools
  configure_git
  final_setup
  
  echo ""
  show_summary
}

main "$@"
