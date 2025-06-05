#!/usr/bin/env bash
# Debian/Ubuntu 一键开发环境配置脚本 (优化版)
# 支持root用户运行、自动配置sudo、修复PATH、SSH配置、脚本内GitHub链接代理等
# 融合了优化的Docker安装和系统检查功能
# 新增：支持根据地区配置镜像源和代理、Docker安装方式选择、使用amix/vimrc增强vim配置

# --- 初始化与错误处理 ---
set -euo pipefail # 遇到错误立即退出，未定义变量视为错误，管道命令中任何一个失败都视为失败
trap 'echo -e "\033[0;31m[ERROR]\033[0m 第${LINENO}行命令执行失败：${BASH_COMMAND}"; exit 1' ERR

# --- 色彩输出定义 ---
RED='\033[0;31m'; GREEN='\033[32;1m'
YELLOW='\033[33;1m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; PURPLE='\033[0;35m'
NC='\033[0m' # 无颜色

# --- 全局变量 ---
IS_ROOT=false               # 是否以root用户运行
TARGET_USER=""              # 目标配置用户名
TARGET_HOME=""              # 目标用户家目录
SUDO_CMD=""                 # sudo命令前缀（普通用户时为"sudo"）
INSTALL_EXTRA_TOOLS=false   # 是否安装额外开发工具
DOCKER_INSTALL_METHOD=""    # Docker安装方式 ("apt" 或 "binary")

# 中国大陆地区配置控制，默认自动检测，可被环境变量覆盖 (true/false/auto)
IN_CHINA="${IN_CHINA:-auto}"
# shellcheck disable=SC2034 # 用于摘要显示
IN_CHINA_AUTO_DETECTED_INFO="" # 存储自动检测的原始信息

# Docker相关配置，可被环境变量覆盖
REGISTRY_MIRROR="${REGISTRY_MIRROR:-auto}"        # Docker镜像源配置 (auto/CN/NONE)
DOCKER_VERSION="${DOCKER_VERSION:-28.2.2}"        # Docker默认版本 (二进制安装时)
DOCKER_COMPOSE_VERSION="${DOCKER_COMPOSE_VERSION:-v2.36.2}" # Docker Compose默认版本 (二进制安装时)

# --- 日志函数 (级别指示符使用英文) ---
log_info()    { echo -e "${BLUE}[INFO]${NC}    $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC}   $*"; }
log_step()    { echo -e "${PURPLE}[STEP]${NC}    $*"; }
log_prompt()  { echo -e "${CYAN}[PROMPT]${NC}  $*"; }

# --- 地区检测与代理配置 ---

# 检测是否在中国大陆
detect_china_region() {
  if [[ "${IN_CHINA}" == "auto" ]]; then
    log_info "自动检测地区..."
    local detected_china="false" # 默认为false

    # 方法1: 检查时区
    local timezone=""
    if [[ -f /etc/timezone ]]; then
      timezone=$(cat /etc/timezone 2>/dev/null || echo "")
    elif command -v timedatectl &>/dev/null; then
      timezone=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "")
    fi
    if [[ "${timezone}" =~ ^Asia/(Shanghai|Chongqing|Harbin|Urumqi)$ ]]; then
      detected_china="true"
      IN_CHINA_AUTO_DETECTED_INFO+="时区(${timezone})符合; "
    fi

    # 方法2: 检查语言环境 (如果未通过时区检测到)
    if [[ "${detected_china}" == "false" ]] && [[ "${LANG:-}" =~ ^zh_CN ]]; then
      detected_china="true"
      IN_CHINA_AUTO_DETECTED_INFO+="语言(${LANG})符合; "
    fi

    # 方法3: 尝试网络检测 (如果以上方法未检测到，作为补充，设置较短超时)
    if [[ "${detected_china}" == "false" ]] && command -v curl &>/dev/null; then
      local ip_info_country=""
      # 使用可靠的IP地理位置服务，设置短超时以避免长时间等待
      # 尝试多个源，依次进行
      if [[ -z "${ip_info_country}" ]]; then
        ip_info_country=$(curl -fsSL --connect-timeout 2 --max-time 4 "https://ipinfo.io/country" 2>/dev/null || echo "")
        if [[ "${ip_info_country}" == "CN" ]]; then
          IN_CHINA_AUTO_DETECTED_INFO+="ipinfo.io(CN); "
        fi
      fi
      if [[ "${ip_info_country}" != "CN" && -z "${ip_info_country}" ]]; then # 如果上一个没成功或者没检测到CN
        ip_info_country=$(curl -fsSL --connect-timeout 2 --max-time 4 "https://myip.ipip.net/country" 2>/dev/null || echo "")
         if [[ "${ip_info_country}" == "CN" ]]; then
          IN_CHINA_AUTO_DETECTED_INFO+="ipip.net(CN); "
        fi
      fi
      # ... 可以添加更多IP检测源

      if [[ "${ip_info_country}" == "CN" ]]; then
        detected_china="true"
      else
        IN_CHINA_AUTO_DETECTED_INFO+="IP检测非CN或失败; "
      fi
    elif [[ "${detected_china}" == "false" ]]; then
        IN_CHINA_AUTO_DETECTED_INFO+="curl不可用跳过IP检测; "
    fi

    IN_CHINA="${detected_china}"
    if [[ "${IN_CHINA}" == "true" ]]; then
      log_info "综合检测结果：判定为中国大陆环境。(${IN_CHINA_AUTO_DETECTED_INFO%??})" # 去掉末尾的分号和空格
    else
      log_info "综合检测结果：判定为非中国大陆环境，使用国际配置。(${IN_CHINA_AUTO_DETECTED_INFO%??})"
    fi
  else
    IN_CHINA_AUTO_DETECTED_INFO="手动设置IN_CHINA=${IN_CHINA}"
    log_info "使用手动指定的地区配置 IN_CHINA=${IN_CHINA}"
  fi
}

# 获取GitHub代理前缀（仅在中国时启用）
get_github_proxy() {
  if [[ "${IN_CHINA}" == "true" ]]; then
    echo "${GITHUB_PROXY:-https://ghfast.top}" # 恢复用户指定的默认代理
  else
    echo ""
  fi
}

GITHUB_DOMAINS_REGEX='^https://(github\.com|raw\.githubusercontent\.com|api\.github\.com|codeload\.github\.com|objects\.githubusercontent\.com|ghcr\.io|gist\.github\.com)'
add_github_proxy() {
  local url="$1"
  local proxy_prefix
  proxy_prefix=$(get_github_proxy)

  if [[ -n "${proxy_prefix}" && "${url}" =~ ${GITHUB_DOMAINS_REGEX} ]]; then
    if [[ "${url}" =~ ^${proxy_prefix}/ ]]; then
      echo "${url}"
    else
      echo "${proxy_prefix}/${url}"
    fi
  else
    echo "${url}"
  fi
}

is_github_url() {
  local url="$1"
  [[ "${url}" =~ ${GITHUB_DOMAINS_REGEX} ]]
}

process_script_github_urls() {
  local script_file="$1"
  local backup_file="${script_file}.$(date +%s).backup"
  local proxy_prefix
  proxy_prefix=$(get_github_proxy)

  if [[ ! -f "${script_file}" ]]; then
    log_warning "脚本文件不存在: ${script_file}"
    return 1
  fi

  if [[ -z "${proxy_prefix}" ]]; then
    log_info "未启用GitHub代理，跳过脚本内GitHub链接处理: $(basename "${script_file}")"
    return 0
  fi

  log_info "处理脚本 $(basename "${script_file}") 中的GitHub链接 (添加代理: ${proxy_prefix})..."
  cp "${script_file}" "${backup_file}"
  log_info "原文件已备份至: ${backup_file}"

  sed -i -E \
    -e "s#(https://)(github\.com)#${proxy_prefix}/\1\2#g" \
    -e "s#(https://)(raw\.githubusercontent\.com)#${proxy_prefix}/\1\2#g" \
    -e "s#(https://)(api\.github\.com)#${proxy_prefix}/\1\2#g" \
    -e "s#(https://)(codeload\.github\.com)#${proxy_prefix}/\1\2#g" \
    -e "s#(https://)(objects\.githubusercontent\.com)#${proxy_prefix}/\1\2#g" \
    -e "s#(https://)(ghcr\.io)#${proxy_prefix}/\1\2#g" \
    -e "s#(https://)(gist\.github\.com)#${proxy_prefix}/\1\2#g" \
    -e "s#${proxy_prefix}/${proxy_prefix}/#${proxy_prefix}/#g" \
    "${script_file}"

  log_success "脚本 $(basename "${script_file}") 内GitHub链接处理完成。"
}

download_and_process_script() {
  local url="$1"
  local output_file="$2"
  local process_internal_links="${3:-auto}"

  log_info "准备下载脚本: ${url}"
  local download_url
  download_url=$(add_github_proxy "${url}")
  log_info "实际下载地址: ${download_url}"

  if ! curl --connect-timeout 10 --max-time 60 -fsSL "${download_url}" -o "${output_file}"; then
    log_error "下载脚本 ${url} 失败！请检查网络或代理配置。"
    return 1
  fi
  chmod +x "${output_file}"

  local should_process_internal_links=false
  if [[ "${process_internal_links}" == "true" ]]; then
    should_process_internal_links=true
  elif [[ "${process_internal_links}" == "auto" ]] && is_github_url "${url}"; then
    should_process_internal_links=true
  fi

  if [[ "${should_process_internal_links}" == "true" ]]; then
    process_script_github_urls "${output_file}"
  else
    log_info "跳过处理脚本 $(basename "${output_file}") 内部的GitHub链接。"
  fi

  log_success "脚本 $(basename "${output_file}") 下载和处理完成。"
}

# --- 用户与权限管理 ---
init_user_info() {
  if [[ "${EUID}" -eq 0 ]]; then
    IS_ROOT=true
    log_info "检测到以root用户运行。"
    # 如果SUDO_USER存在且有效且不是root，则作为目标用户
    if [[ -n "${SUDO_USER:-}" ]] && id "${SUDO_USER}" &>/dev/null && [[ "${SUDO_USER}" != "root" ]]; then
      TARGET_USER="${SUDO_USER}"
      log_info "检测到 SUDO_USER: ${TARGET_USER} (非root)，将为此用户配置。"
    else
      # 允许配置root用户，或者如果需要，可以提示输入其他用户
      # 为了允许直接为root配置，如果SUDO_USER是root或未设置，则TARGET_USER为root
      if [[ -n "${SUDO_USER:-}" ]] && [[ "${SUDO_USER}" == "root" ]]; then
        log_info "SUDO_USER是root，将为root用户配置。"
        TARGET_USER="root"
      elif [[ -z "${SUDO_USER:-}" ]]; then
        log_info "未检测到SUDO_USER，将为当前root用户配置。"
        TARGET_USER="root"
      else
        # SUDO_USER无效的情况，这里也默认为root，或按原逻辑提示
        log_warning "SUDO_USER (${SUDO_USER:-<未设置>}) 无效或非预期，将为root用户配置。"
        TARGET_USER="root"
      fi
    fi

    if [[ "${TARGET_USER}" == "root" ]]; then
        TARGET_HOME="/root"
    else
        TARGET_HOME=$(eval echo "~${TARGET_USER}")
    fi
    SUDO_CMD=""
    log_info "配置将应用于用户: ${TARGET_USER}, 其家目录为: ${TARGET_HOME}"
  else
    IS_ROOT=false
    TARGET_USER="${USER}"
    TARGET_HOME="${HOME}"
    SUDO_CMD="sudo"
    log_info "检测到以普通用户 ${TARGET_USER} 运行。"
    if ! sudo -n true 2>/dev/null; then
        log_warning "当前用户 ${TARGET_USER} 可能没有免密sudo权限。"
        log_warning "脚本执行过程中可能需要多次输入密码。"
        read -rp "$(log_prompt '是否继续? (y/N): ')" confirm_continue
        if [[ "${confirm_continue,,}" != "y" ]]; then
            log_info "操作已取消。"
            exit 0
        fi
    fi
  fi
}

configure_installation_options() {
  log_step "配置安装选项"
  echo
  log_prompt "1. Docker安装方式选择："
  echo "  • apt方式: 使用Docker官方APT仓库安装 (推荐，易于更新)"
  echo "  • 二进制方式: 下载Docker二进制文件安装 (可选择特定版本，适合离线或特定需求)"
  echo
  while [[ -z "${DOCKER_INSTALL_METHOD}" ]]; do
    read -rp "$(log_prompt '请选择Docker安装方式 (apt/binary) [默认: apt]: ')" docker_method_choice
    docker_method_choice="${docker_method_choice:-apt}"
    case "${docker_method_choice,,}" in
      "apt")
        DOCKER_INSTALL_METHOD="apt"
        log_success "已选择Docker安装方式：APT仓库"
        ;;
      "binary" | "bin")
        DOCKER_INSTALL_METHOD="binary"
        log_success "已选择Docker安装方式：二进制文件"
        ;;
      *)
        log_error "无效选择。请输入 'apt' 或 'binary'。"
        ;;
    esac
  done
  echo
  log_prompt "2. 是否安装额外开发工具？"
  echo "   这些工具包括：Node.js (LTS), Python3-pip, JDK, Go, Ruby, PHP,"
  echo "   数据库客户端 (MySQL, PostgreSQL, Redis, SQLite), jq, yq, Visual Studio Code."
  echo
  read -rp "$(log_prompt '是否安装额外开发工具？ (y/N) [默认: N]: ')" install_extra_choice
  if [[ "${install_extra_choice,,}" == "y" ]]; then
    INSTALL_EXTRA_TOOLS=true
    log_success "已选择：安装额外开发工具。"
  else
    INSTALL_EXTRA_TOOLS=false
    log_info "已选择：跳过额外开发工具的安装。"
  fi
  echo
}

# --- 状态文件管理 ---
get_status_file() {
  echo "${TARGET_HOME}/.dev-env-setup-status"
}
mark_completed()   { echo "$1" >> "$(get_status_file)"; }
is_completed()     { [[ -f "$(get_status_file)" ]] && grep -qx "$1" "$(get_status_file)"; }
skip_if_completed(){ if is_completed "$1"; then log_warning "步骤 [$1] 已完成，跳过。"; return 0; else return 1; fi; }

# --- 系统与环境准备 ---
fix_path() {
  skip_if_completed "fix_path" && return
  log_step "检查并修复PATH环境变量"
  local common_paths=(
    "/usr/local/sbin" "/usr/local/bin" "/usr/sbin" "/usr/bin" "/sbin" "/bin" "/snap/bin"
  )
  local current_path="${PATH}"
  local paths_to_add=()
  for path_to_check in "${common_paths[@]}"; do
    if [[ ":${current_path}:" != *":${path_to_check}:"* ]] && [[ -d "${path_to_check}" ]]; then
      paths_to_add+=("${path_to_check}")
    fi
  done
  if [[ ${#paths_to_add[@]} -gt 0 ]]; then
    log_info "检测到以下路径不在PATH中或目录不存在，将尝试添加存在的目录: ${paths_to_add[*]}"
    export PATH="${PATH}:$(IFS=:; echo "${paths_to_add[*]}")"
    log_info "当前会话PATH已更新: ${PATH}"
    local profile_d_script="/etc/profile.d/dev_env_custom_paths.sh"
    log_info "正在将PATH配置写入 ${profile_d_script} ..."
    local profile_content="# 由开发环境脚本添加的自定义PATH\n"
    for path_to_add in "${paths_to_add[@]}"; do
      profile_content+="export PATH=\"\${PATH}:${path_to_add}\"\n"
    done
    echo -e "${profile_content}" | ${SUDO_CMD} tee "${profile_d_script}" >/dev/null
    ${SUDO_CMD} chmod +x "${profile_d_script}"
    log_success "PATH配置已写入 ${profile_d_script}。重新登录后生效。"
  else
    log_info "PATH环境变量包含所有常用路径，无需修改。"
  fi
  mark_completed "fix_path"
}

setup_sudo() {
  skip_if_completed "setup_sudo" && return
  log_step "配置sudo和用户权限"
  if [[ "${IS_ROOT}" == "true" ]]; then
    # 如果是root用户，且目标用户不是root，则为目标用户配置sudo
    if [[ "${TARGET_USER}" != "root" ]]; then
        if ! command -v sudo &>/dev/null; then
          log_info "sudo 未安装，正在安装..."
          apt-get update -qq
          ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y sudo # SUDO_CMD为空
        fi
        local usermod_cmd="usermod"
        if ! command -v usermod &>/dev/null && [[ -x "/usr/sbin/usermod" ]]; then
            usermod_cmd="/usr/sbin/usermod"
        elif ! command -v usermod &>/dev/null; then
            log_error "usermod 命令未找到，无法将用户添加到sudo组。"
            return 1
        fi
        if ! groups "${TARGET_USER}" | grep -qw sudo; then
          log_info "将用户 ${TARGET_USER} 添加到 sudo 组..."
          "${usermod_cmd}" -aG sudo "${TARGET_USER}" # 直接执行，因为当前是root
          log_info "用户 ${TARGET_USER} 已添加到 sudo 组。可能需要重新登录以使组更改生效。"
        fi
        if ! grep -q "^\%sudo\s\+ALL=(ALL:ALL)\s\+ALL" /etc/sudoers; then
          log_info "配置 /etc/sudoers 以允许 sudo 组成员执行所有命令..."
          cp /etc/sudoers /etc/sudoers.bak.$(date +%s)
          echo "%sudo   ALL=(ALL:ALL) ALL" >> /etc/sudoers
        fi
        log_success "Sudo (为 ${TARGET_USER}) 配置完成。"
    else
        log_info "目标用户是root，无需配置sudo组。"
    fi
  else # 普通用户运行
    if ! command -v sudo &>/dev/null; then
      log_error "sudo 命令未安装。请先以root用户运行此脚本一次，或手动安装sudo。"
      exit 1
    fi
    log_info "以普通用户运行，假定sudo已配置或将在需要时提示密码。"
  fi
  mark_completed "setup_sudo"
}

# --- 辅助函数：用户操作封装 ---
run_as_user() {
  local cmd_to_run="$*"
  if [[ "${IS_ROOT}" == "true" ]] && [[ "${USER}" != "${TARGET_USER}" ]] && [[ "${TARGET_USER}" != "root" ]]; then
    su - "${TARGET_USER}" -c "cd \"${TARGET_HOME}\" && bash -c \"${cmd_to_run//\"/\\\"}\""
  else # 当前用户是目标用户，或者目标用户是root (此时当前用户也是root)
    (cd "${TARGET_HOME}" && bash -c "${cmd_to_run}")
  fi
}
create_user_dir() {
  local dir_path="$1"
  if [[ "${IS_ROOT}" == "true" ]] && [[ "${TARGET_USER}" != "root" ]]; then
    mkdir -p "${dir_path}"
    chown "${TARGET_USER}:${TARGET_USER}" "${dir_path}"
  else
    mkdir -p "${dir_path}"
    # 如果是root为自己创建，则不需要chown
  fi
}
write_user_file() {
  local file_path="$1"
  local content="$2"
  if [[ "${IS_ROOT}" == "true" ]] && [[ "${TARGET_USER}" != "root" ]]; then
    echo -e "${content}" > "${file_path}"
    chown "${TARGET_USER}:${TARGET_USER}" "${file_path}"
  else
    echo -e "${content}" > "${file_path}"
  fi
}

# --- 系统检查与依赖 ---
check_system() {
  log_info "检查操作系统类型..."
  if ! command -v apt >/dev/null; then
    log_error "此脚本仅支持基于 apt 的 Debian/Ubuntu 系统。"
    exit 1
  fi
  log_success "检测到支持的系统类型 (Debian/Ubuntu based)。"
  if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    log_info "系统信息: ${PRETTY_NAME:-"${ID} ${VERSION_ID}"}"
  else
    log_warning "无法读取 /etc/os-release 获取详细系统信息。"
  fi
}

check_iptables() {
  skip_if_completed "check_iptables" && return
  log_step "检查iptables (Docker依赖)"
  if command -v iptables &>/dev/null; then
    log_success "iptables 已安装。"
  else
    log_info "iptables 未安装，尝试安装..."
    # shellcheck source=/dev/null
    . /etc/os-release
    if [[ "${ID,,}" == "debian" && ("${VERSION_ID}" == "11" || "${VERSION_ID}" == "12" || "${VERSION_ID}" == "13") ]] || \
       [[ "${ID,,}" == "ubuntu" && ("${VERSION_ID}" == "20.04" || "${VERSION_ID}" == "22.04" || "${VERSION_ID}" == "24.04") ]]; then
      if ! ${SUDO_CMD} apt-get update -qq; then log_warning "check_iptables中apt-get update失败"; fi
      if ! ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y iptables iptables-persistent; then
        log_error "iptables 及 iptables-persistent 安装失败，即使在支持的系统版本上。"
        return 1
      fi
      log_success "iptables 及 iptables-persistent 安装完成。"
    else
      log_warning "当前系统 ${ID} ${VERSION_ID} 可能需要特定方式安装iptables，或已使用nftables。"
      if ! ${SUDO_CMD} apt-get update -qq; then log_warning "check_iptables中apt-get update失败"; fi
      if ! (${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y iptables); then
          log_error "iptables (通用尝试) 安装失败。请手动安装。"
          return 1
      else
          log_success "iptables (通用尝试) 安装完成。"
      fi
    fi
  fi
  mark_completed "check_iptables"
}

# --- 步骤 1：配置 SSH 服务 ---
setup_ssh() {
  skip_if_completed "setup_ssh" && return
  log_step "配置SSH服务"
  log_info "配置 SSH：允许 root 登录 (PermitRootLogin yes) 并启用密码认证 (PasswordAuthentication yes)..."
  local sshd_config_file="/etc/ssh/sshd_config"
  if [[ ! -f "${sshd_config_file}" ]]; then
    log_warning "SSH配置文件 ${sshd_config_file} 未找到！如果需要SSH服务，请先安装openssh-server。"
    # 不返回错误，因为SSH服务可能是可选的
    return
  fi
  ${SUDO_CMD} cp -n "${sshd_config_file}" "${sshd_config_file}.bak.$(date +%s)" 2>/dev/null || true
  ${SUDO_CMD} sed -i -E \
    -e 's/^#?\s*PermitRootLogin\s+.*/PermitRootLogin yes/' \
    -e 's/^#?\s*PasswordAuthentication\s+.*/PasswordAuthentication yes/' \
    "${sshd_config_file}"
  log_info "尝试重启SSH服务以应用配置..."
  if command -v systemctl &>/dev/null; then
    ${SUDO_CMD} systemctl restart sshd
  elif command -v service &>/dev/null; then
    ${SUDO_CMD} service ssh restart
  else
    log_warning "无法自动重启SSH服务。请手动重启。"
  fi
  log_success "SSH 服务配置尝试完成。请检查服务状态。"
  mark_completed "setup_ssh"
}

# --- 步骤 2：生成用户SSH密钥对并配置免密登录到localhost ---
setup_ssh_keys() {
  skip_if_completed "setup_ssh_keys" && return
  log_step "为用户 ${TARGET_USER} 配置SSH密钥对及免密登录localhost"
  local ssh_dir="${TARGET_HOME}/.ssh"
  local private_key_path="${ssh_dir}/id_rsa"
  local public_key_path="${ssh_dir}/id_rsa.pub"
  local authorized_keys_path="${ssh_dir}/authorized_keys"
  local known_hosts_path="${ssh_dir}/known_hosts"
  create_user_dir "${ssh_dir}"
  run_as_user "chmod 700 '${ssh_dir}'"
  if [[ ! -f "${private_key_path}" ]]; then
    log_info "为用户 ${TARGET_USER} 生成SSH密钥对 (rsa, 4096 bits)..."
    run_as_user "ssh-keygen -t rsa -b 4096 -f '${private_key_path}' -N '' -C '${TARGET_USER}@$(hostname -f 2>/dev/null || hostname)'"
    log_success "SSH密钥对生成完成: ${private_key_path}"
  else
    log_warning "SSH私钥 ${private_key_path} 已存在，跳过生成。"
  fi
  if [[ -f "${public_key_path}" ]]; then
    log_info "将公钥 ${public_key_path} 添加到 ${authorized_keys_path}..."
    local public_key_content
    public_key_content=$(run_as_user "cat '${public_key_path}'")
    if [[ -n "${public_key_content}" ]]; then
      run_as_user "touch '${authorized_keys_path}' && chmod 600 '${authorized_keys_path}'"
      if ! run_as_user "grep -Fq -- '${public_key_content}' '${authorized_keys_path}'"; then
        run_as_user "echo '${public_key_content}' >> '${authorized_keys_path}'"
        log_info "公钥已添加到 ${authorized_keys_path}。"
      else
        log_warning "公钥已存在于 ${authorized_keys_path}。"
      fi
    else
      log_warning "无法读取公钥内容 ${public_key_path}。"
    fi
  else
    log_warning "公钥文件 ${public_key_path} 未找到，无法添加到authorized_keys。"
  fi
  run_as_user "chmod 600 '${private_key_path}'"
  log_info "添加localhost和127.0.0.1到 ${known_hosts_path}..."
  run_as_user "ssh-keyscan -H 127.0.0.1 >> '${known_hosts_path}' 2>/dev/null || true"
  run_as_user "ssh-keyscan -H localhost >> '${known_hosts_path}' 2>/dev/null || true"
  run_as_user "sort -u -o '${known_hosts_path}' '${known_hosts_path}'"
  run_as_user "chmod 644 '${known_hosts_path}'"
  log_info "测试SSH免密登录到localhost (用户: ${TARGET_USER})..."
  local test_ssh_cmd="ssh -o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=no ${TARGET_USER}@127.0.0.1 'echo SSH_CONNECTION_SUCCESSFUL'"
  local output
  if output=$(run_as_user "${test_ssh_cmd}" 2>/dev/null) && [[ "$output" == "SSH_CONNECTION_SUCCESSFUL" ]]; then
    log_success "SSH免密登录到localhost测试成功。"
  else
    log_warning "SSH免密登录到localhost测试失败。请检查SSH配置和密钥权限。"
    log_warning "失败的命令: ${test_ssh_cmd}"
    log_warning "输出: ${output:-<无输出>}"
  fi
  log_success "用户 ${TARGET_USER} 的SSH密钥配置完成。"
  mark_completed "setup_ssh_keys"
}

# --- 步骤 3：配置APT镜像源 (仅在中国时执行) ---
setup_aliyun_mirror() {
  skip_if_completed "aliyun_mirror" && return
  if [[ "${IN_CHINA}" != "true" ]]; then
    log_info "非中国大陆地区，跳过APT镜像源配置。"
    mark_completed "aliyun_mirror"
    return
  fi
  log_step "配置APT阿里云镜像源"
  # shellcheck source=/dev/null
  . /etc/os-release
  if [[ -z "${ID:-}" ]] || [[ -z "${VERSION_CODENAME:-}" ]]; then
    log_error "无法获取操作系统ID或版本代号，跳过阿里云镜像源配置。"
    return 1
  fi
  log_info "备份原始 /etc/apt/sources.list 至 /etc/apt/sources.list.bak.$(date +%s)..."
  ${SUDO_CMD} cp -n /etc/apt/sources.list /etc/apt/sources.list.bak.$(date +%s)
  local sources_list_content=""
  log_info "为 ${ID} ${VERSION_CODENAME} 配置阿里云镜像源..."
  if [[ "${ID,,}" == "ubuntu" ]]; then
    sources_list_content=$(cat <<EOF
deb https://mirrors.aliyun.com/ubuntu/ ${VERSION_CODENAME} main restricted universe multiverse
deb-src https://mirrors.aliyun.com/ubuntu/ ${VERSION_CODENAME} main restricted universe multiverse
deb https://mirrors.aliyun.com/ubuntu/ ${VERSION_CODENAME}-security main restricted universe multiverse
deb-src https://mirrors.aliyun.com/ubuntu/ ${VERSION_CODENAME}-security main restricted universe multiverse
deb https://mirrors.aliyun.com/ubuntu/ ${VERSION_CODENAME}-updates main restricted universe multiverse
deb-src https://mirrors.aliyun.com/ubuntu/ ${VERSION_CODENAME}-updates main restricted universe multiverse
deb https://mirrors.aliyun.com/ubuntu/ ${VERSION_CODENAME}-backports main restricted universe multiverse
deb-src https://mirrors.aliyun.com/ubuntu/ ${VERSION_CODENAME}-backports main restricted universe multiverse
EOF
)
  elif [[ "${ID,,}" == "debian" ]]; then
    sources_list_content=$(cat <<EOF
deb https://mirrors.aliyun.com/debian/ ${VERSION_CODENAME} main non-free contrib non-free-firmware
deb-src https://mirrors.aliyun.com/debian/ ${VERSION_CODENAME} main non-free contrib non-free-firmware
deb https://mirrors.aliyun.com/debian-security/ ${VERSION_CODENAME}-security main non-free contrib non-free-firmware
deb-src https://mirrors.aliyun.com/debian-security/ ${VERSION_CODENAME}-security main non-free contrib non-free-firmware
deb https://mirrors.aliyun.com/debian/ ${VERSION_CODENAME}-updates main non-free contrib non-free-firmware
deb-src https://mirrors.aliyun.com/debian/ ${VERSION_CODENAME}-updates main non-free contrib non-free-firmware
deb https://mirrors.aliyun.com/debian/ ${VERSION_CODENAME}-backports main non-free contrib non-free-firmware
deb-src https://mirrors.aliyun.com/debian/ ${VERSION_CODENAME}-backports main non-free contrib non-free-firmware
EOF
)
  else
    log_warning "不支持的发行版 ${ID}，跳过阿里云镜像源配置。"
    return
  fi
  echo "${sources_list_content}" | ${SUDO_CMD} tee /etc/apt/sources.list >/dev/null
  log_success "阿里云APT镜像源配置完成。"
  log_info "立即执行 apt update 使新镜像源生效..."
  if ! ${SUDO_CMD} apt-get update -qq; then
    log_error "在新镜像源 (${ID} ${VERSION_CODENAME} 阿里云) 上执行 apt-get update 失败！"
    log_warning "请手动检查 /etc/apt/sources.list 文件内容、网络连接以及镜像源状态。"
    log_warning "后续操作可能因包列表未更新而失败。"
  else
    log_success "apt-get update 在新镜像源上执行成功。"
  fi
  mark_completed "aliyun_mirror"
}

# --- 步骤 4：更新系统 ---
update_system() {
  skip_if_completed "system_update" && return
  log_step "更新系统软件包"
  log_info "执行 apt-get update ..."
  if ! ${SUDO_CMD} apt-get update -qq; then
    log_error "apt-get update 失败！请检查网络和APT源配置。"
    log_warning "系统可能无法正确更新，后续软件包安装也可能因此受影响。"
  fi
  log_info "执行 apt-get upgrade -y ..."
  if ! ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get upgrade -y; then
    log_warning "apt-get upgrade 执行时遇到问题或部分包未能升级。"
    log_info "这可能不是致命错误，脚本将继续。"
  fi
  log_info "执行 apt-get autoremove -y 和 apt-get clean..."
  ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get autoremove -y >/dev/null 2>&1
  ${SUDO_CMD} apt-get clean >/dev/null 2>&1
  log_success "系统更新和升级尝试完成。"
  mark_completed "system_update"
}

# --- 步骤 5：安装基础工具 ---
install_basic_tools() {
  skip_if_completed "basic_tools" && return
  log_step "安装基础开发工具"

  log_info "再次确保APT包列表为最新 (apt-get update)..."
  if ! ${SUDO_CMD} apt-get update -qq; then
    log_error "在安装基础工具前执行 apt-get update 失败！"
    log_warning "这可能导致无法找到软件包。请检查网络和APT源配置。"
    return 1 # 强制退出，因为这很可能是后续所有apt install失败的原因
  fi

  # 核心基础工具
  local core_tools=(
    curl wget git vim build-essential software-properties-common
    apt-transport-https ca-certificates gnupg lsb-release unzip
    openssh-server jq
  )
  log_info "安装核心基础工具: ${core_tools[*]} ..."
  if ! ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y "${core_tools[@]}"; then
    log_error "核心基础工具 (${core_tools[*]}) 安装失败！"
    if ! dpkg -s build-essential >/dev/null 2>&1; then
        log_error "'build-essential' 未能成功安装。这是编译软件的关键包。"
        log_error "请手动运行: sudo apt-get update && sudo apt-get install build-essential"
        log_error "并检查错误信息。脚本将中止。"
        exit 1 # 中止脚本
    fi
    log_warning "部分核心工具可能未安装成功，脚本将继续，但后续步骤可能受影响。"
  else
    log_success "核心基础工具安装完成/已是最新版本。"
  fi

  # 附加基础工具
  local additional_tools=(
    tree htop neofetch fontconfig
  )
  local successfully_installed_additional=()
  local failed_additional_tools=()

  log_info "尝试安装附加基础工具: ${additional_tools[*]} ..."
  for tool in "${additional_tools[@]}"; do
    if ! dpkg -s "${tool}" >/dev/null 2>&1; then
      log_info "尝试安装 ${tool}..."
      # 为每个包单独执行install，以便捕获特定包的失败
      if ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y "${tool}"; then
        log_success "${tool} 安装成功。"
        successfully_installed_additional+=("${tool}")
      else
        log_warning "附加工具 ${tool} 安装失败或在源中找不到。"
        failed_additional_tools+=("${tool}")
      fi
    else
      log_info "${tool} 已安装，跳过。"
      successfully_installed_additional+=("${tool}") # 也算成功
    fi
  done

  if [[ ${#successfully_installed_additional[@]} -gt 0 ]]; then
      log_success "成功安装/确认的附加工具: ${successfully_installed_additional[*]}"
  fi
  if [[ ${#failed_additional_tools[@]} -gt 0 ]]; then
    log_warning "以下附加工具未能成功安装 (可能是可选的): ${failed_additional_tools[*]}"
  fi

  log_success "基础工具安装流程执行完毕。" # 即使部分附加工具失败，也认为主要流程完成
  mark_completed "basic_tools"
}


# --- 步骤 6：安装与配置 Zsh, Oh My Zsh, Powerlevel10k ---
install_zsh() {
  skip_if_completed "zsh" && return
  log_step "安装Zsh"
  if ! ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y zsh; then log_error "Zsh安装失败"; return 1; fi
  local chsh_cmd="chsh"
  if ! command -v chsh &>/dev/null && [[ -x "/usr/bin/chsh" ]]; then
      chsh_cmd="/usr/bin/chsh"
  elif ! command -v chsh &>/dev/null; then
      log_error "chsh 命令未找到，无法更改用户默认shell。"
      return 1
  fi
  local zsh_path
  zsh_path=$(command -v zsh)
  if [[ "$(getent passwd "${TARGET_USER}" | cut -d: -f7)" != "${zsh_path}" ]]; then
    log_info "将用户 ${TARGET_USER} 的默认shell更改为 ${zsh_path}..."
    if ! ${SUDO_CMD} "${chsh_cmd}" -s "${zsh_path}" "${TARGET_USER}"; then
      log_error "使用chsh更改shell失败。"
    else
      log_warning "用户 ${TARGET_USER} 需要重新登录以使默认shell的更改生效。"
    fi
  else
    log_info "用户 ${TARGET_USER} 的默认shell已经是zsh。"
  fi
  log_success "zsh 安装完成。"
  mark_completed "zsh"
}

install_oh_my_zsh() {
  skip_if_completed "oh_my_zsh" && return
  log_step "为用户 ${TARGET_USER} 安装Oh My Zsh"
  local oh_my_zsh_dir="${TARGET_HOME}/.oh-my-zsh"
  if [[ ! -d "${oh_my_zsh_dir}" ]]; then
    log_info "安装 Oh My Zsh..."
    local install_script_url='https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh'
    local temp_install_script
    temp_install_script="$(mktemp --tmpdir ohmyzsh_install.XXXXXX.sh)"
    if ! download_and_process_script "${install_script_url}" "${temp_install_script}" "auto"; then
        log_error "下载Oh My Zsh安装脚本失败。"
        rm -f "${temp_install_script}"
        return 1
    fi
    log_info "以用户 ${TARGET_USER} 身份执行Oh My Zsh安装脚本..."
    if run_as_user "RUNZSH=no CHSH=no KEEP_ZSHRC=yes sh '${temp_install_script}' --unattended"; then
      log_success "Oh My Zsh 安装完成。"
    else
      log_error "Oh My Zsh 安装失败。"
    fi
    rm -f "${temp_install_script}"
  else
    log_warning "Oh My Zsh 目录 (${oh_my_zsh_dir}) 已存在，跳过安装。"
  fi
  mark_completed "oh_my_zsh"
}

install_powerlevel10k() {
  skip_if_completed "powerlevel10k" && return
  log_step "为用户 ${TARGET_USER} 安装Powerlevel10k主题"
  local p10k_theme_dir="${TARGET_HOME}/.oh-my-zsh/custom/themes/powerlevel10k"
  local zshrc_file_path="${TARGET_HOME}/.zshrc"
  if [[ ! -d "${p10k_theme_dir}" ]]; then
    log_info "安装 Powerlevel10k 主题..."
    create_user_dir "$(dirname "${p10k_theme_dir}")"
    local p10k_repo_url
    p10k_repo_url=$(add_github_proxy 'https://github.com/romkatv/powerlevel10k.git')
    if ! run_as_user "git clone --depth=1 '${p10k_repo_url}' '${p10k_theme_dir}'"; then
        log_error "克隆Powerlevel10k仓库失败。"
        return 1
    fi
    log_info "Powerlevel10k 主题已克隆到 ${p10k_theme_dir}"
  else
    log_warning "Powerlevel10k 主题目录 (${p10k_theme_dir}) 已存在，跳过克隆。"
  fi
  log_info "配置 ${zshrc_file_path} 以使用 Powerlevel10k..."
  if [[ ! -f "${zshrc_file_path}" ]]; then
    log_warning "${zshrc_file_path} 未找到。Oh My Zsh应该已创建它。如果问题持续，请检查。"
    run_as_user "echo '# Minimal .zshrc for Powerlevel10k' > '${zshrc_file_path}'"
    run_as_user "echo 'export ZSH=\"${TARGET_HOME}/.oh-my-zsh\"' >> '${zshrc_file_path}'"
    run_as_user "echo 'plugins=(git)' >> '${zshrc_file_path}'"
    run_as_user "echo 'source \$ZSH/oh-my-zsh.sh' >> '${zshrc_file_path}'"
  fi
  if run_as_user "grep -q '^ZSH_THEME=' '${zshrc_file_path}'"; then
    run_as_user "sed -i 's|^ZSH_THEME=.*|ZSH_THEME=\"powerlevel10k/powerlevel10k\"|' '${zshrc_file_path}'"
  else
    run_as_user "sed -i '/^plugins=(/a ZSH_THEME=\"powerlevel10k/powerlevel10k\"' '${zshrc_file_path}' || echo 'ZSH_THEME=\"powerlevel10k/powerlevel10k\"' >> '${zshrc_file_path}'"
  fi
  local p10k_instant_prompt_config='if [[ -r "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh" ]]; then source "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh"; fi'
  if ! run_as_user "grep -Fq '${p10k_instant_prompt_config}' '${zshrc_file_path}'"; then
    run_as_user "echo '${p10k_instant_prompt_config}' | cat - '${zshrc_file_path}' > '${TARGET_HOME}/.zshrc.tmp' && mv '${TARGET_HOME}/.zshrc.tmp' '${zshrc_file_path}'"
    if [[ "$IS_ROOT" == "true" ]] && [[ "${TARGET_USER}" != "root" ]]; then chown "${TARGET_USER}:${TARGET_USER}" "${zshrc_file_path}"; fi
  fi
  if ! run_as_user "grep -q 'POWERLEVEL9K_DISABLE_CONFIGURATION_WIZARD' '${zshrc_file_path}'"; then
     run_as_user "echo 'typeset -g POWERLEVEL9K_DISABLE_CONFIGURATION_WIZARD=true' >> '${zshrc_file_path}'"
  fi
  log_success "Powerlevel10k 主题安装和初步配置完成。"
  log_info "请重新登录或启动新的zsh会话。您可能需要运行 'p10k configure' 来个性化您的提示符。"
  mark_completed "powerlevel10k"
}

# --- 步骤 7：配置 Vim (使用amix/vimrc + Catppuccin主题) ---
configure_vim() {
  skip_if_completed "vim_config" && return
  log_step "配置Vim (amix/vimrc 增强配置 + Catppuccin 主题)"

  local vim_runtime_dir="${TARGET_HOME}/.vim_runtime"
  local my_configs_path="${vim_runtime_dir}/my_configs.vim"

  # 安装 amix/vimrc
  if [[ ! -d "${vim_runtime_dir}" ]]; then
    log_info "安装 amix/vimrc 增强配置..."
    local amix_vimrc_repo_url
    amix_vimrc_repo_url=$(add_github_proxy 'https://github.com/amix/vimrc.git')

    if ! run_as_user "git clone --depth=1 '${amix_vimrc_repo_url}' '${vim_runtime_dir}'"; then
      log_error "克隆 amix/vimrc 仓库失败。"
      return 1
    fi

    log_info "执行 amix/vimrc 安装脚本..."
    if ! run_as_user "sh '${vim_runtime_dir}/install_awesome_vimrc.sh'"; then
      log_error "amix/vimrc 安装脚本执行失败。"
      return 1
    fi

    log_success "amix/vimrc 基础配置安装完成。"
  else
    log_warning "amix/vimrc 目录 (${vim_runtime_dir}) 已存在，跳过基础安装。"
  fi

  # 下载并安装 Catppuccin 主题
  log_info "安装 Catppuccin Vim 主题..."
  local catppuccin_theme_dir="${vim_runtime_dir}/sources_non_forked/catppuccin-vim"

  if [[ ! -d "${catppuccin_theme_dir}" ]]; then
    local catppuccin_repo_url
    catppuccin_repo_url=$(add_github_proxy 'https://github.com/catppuccin/vim.git')

    if run_as_user "git clone --depth=1 '${catppuccin_repo_url}' '${catppuccin_theme_dir}'"; then
      log_success "Catppuccin 主题已安装到 ${catppuccin_theme_dir}。"
    else
      log_warning "下载 Catppuccin Vim 主题失败。将使用 amix/vimrc 默认主题。"
    fi
  else
    log_info "Catppuccin 主题目录已存在，跳过下载。"
  fi

  # 配置 my_configs.vim 以使用 Catppuccin 主题
  log_info "配置个人 Vim 设置 (${my_configs_path})..."

  local catppuccin_config
  read -r -d '' catppuccin_config << 'EOF' || true
" ===== 个人 Vim 配置 (由开发环境脚本生成) =====

" 启用真彩色支持
if has("termguicolors")
  set termguicolors
endif

" Catppuccin 主题配置
let g:catppuccin_flavour = "latte"  " 可选: latte, frappe, macchiato, mocha

" 应用 Catppuccin 主题
try
  execute 'colorscheme catppuccin_' . g:catppuccin_flavour
catch
  " 如果 Catppuccin 主题不可用，回退到 amix/vimrc 默认主题
  try
    colorscheme peaksea
  catch
    colorscheme default
  endtry
endtry

" 额外的个人偏好设置
set number                    " 显示行号
set relativenumber           " 显示相对行号
set cursorline               " 高亮当前行
set mouse=a                  " 启用鼠标支持
set clipboard=unnamedplus    " 使用系统剪贴板

" 搜索设置
set ignorecase               " 搜索时忽略大小写
set smartcase                " 有大写字母时精确匹配

" 缩进设置
set expandtab                " 将 tab 转换为空格
set tabstop=4                " tab 宽度
set shiftwidth=4             " 缩进宽度
set softtabstop=4            " 软 tab 宽度

" 文件类型特定缩进
autocmd FileType javascript,typescript,json,html,css,scss,yaml,yml setlocal tabstop=2 shiftwidth=2 softtabstop=2
autocmd FileType python setlocal tabstop=4 shiftwidth=4 softtabstop=4
autocmd FileType go setlocal tabstop=4 shiftwidth=4 softtabstop=4 noexpandtab

" 快捷键映射
nnoremap <leader>ev :vsplit ~/.vim_runtime/my_configs.vim<CR>
nnoremap <leader>sv :source ~/.vim_runtime/my_configs.vim<CR>

" ===== 个人配置结束 =====
EOF

  # 检查是否已有配置，避免重复添加
  if [[ ! -f "${my_configs_path}" ]] || ! run_as_user "grep -q '个人 Vim 配置.*开发环境脚本' '${my_configs_path}'"; then
    run_as_user "echo '${catppuccin_config}' >> '${my_configs_path}'"
    log_info "个人 Vim 配置已添加到 ${my_configs_path}。"
  else
    log_info "检测到个人配置已存在，跳过添加。"
  fi

  log_success "Vim 配置完成！"
  log_info "配置详情："
  log_info "  • 基础配置: amix/vimrc awesome 版本"
  log_info "  • 主题: Catppuccin Latte (浅色主题)"
  log_info "  • 个人配置文件: ${my_configs_path}"
  log_info "  • 编辑个人配置: <leader>ev (在 Vim 中)"
  log_info "  • 重载个人配置: <leader>sv (在 Vim 中)"
  log_info "使用说明："
  log_info "  • amix/vimrc 包含大量有用的插件和配置"
  log_info "  • 如需更换主题风味，编辑 ${my_configs_path} 中的 g:catppuccin_flavour"
  log_info "  • 可选风味: latte(浅色), frappe(暖色), macchiato(深色), mocha(最深色)"

  mark_completed "vim_config"
}

# --- 步骤 8：安装与配置 tmux ---
install_tmux() {
  skip_if_completed "tmux_install" && return
  log_step "安装tmux"
  if ! command -v tmux &>/dev/null; then
    log_info "安装 tmux..."
    if ! ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y tmux; then log_error "tmux安装失败"; return 1; fi
    log_success "tmux 安装完成。"
  else
    log_warning "tmux 已安装 (版本: $(tmux -V 2>/dev/null || echo unknown))，跳过安装。"
  fi
  mark_completed "tmux_install"
}

configure_tmux() {
  skip_if_completed "tmux_config" && return
  log_step "为用户 ${TARGET_USER} 配置tmux"
  local tmux_conf_path="${TARGET_HOME}/.tmux.conf"
  local tmux_plugins_base_dir="${TARGET_HOME}/.tmux/plugins"
  local tpm_dir="${tmux_plugins_base_dir}/tpm"
  if [[ ! -d "${tpm_dir}" ]]; then
    log_info "安装 TPM (Tmux Plugin Manager)..."
    create_user_dir "$(dirname "${tpm_dir}")"
    local tpm_repo_url
    tpm_repo_url=$(add_github_proxy 'https://github.com/tmux-plugins/tpm')
    if ! run_as_user "git clone --depth=1 '${tpm_repo_url}' '${tpm_dir}'"; then
        log_error "克隆TPM仓库失败。"
    else
        log_success "TPM 安装完成。"
    fi
  else
    log_warning "TPM 目录 (${tpm_dir}) 已存在，跳过克隆。"
  fi
  log_info "生成 .tmux.conf 配置文件 (${tmux_conf_path})..."
  local tmux_conf_content
  read -r -d '' tmux_conf_content << EOF || true
set -g default-terminal "screen-256color"
set -g mouse on
set -g history-limit 10000
set -g base-index 1
setw -g pane-base-index 1
setw -g automatic-rename on
bind r source-file ~/.tmux.conf \; display "tmux.conf reloaded!"
bind | split-window -h -c "#{pane_current_path}"
bind - split-window -v -c "#{pane_current_path}"
unbind '"'
unbind %
bind h select-pane -L
bind j select-pane -D
bind k select-pane -U
bind l select-pane -R
bind -r H resize-pane -L 5
bind -r J resize-pane -D 5
bind -r K resize-pane -U 5
bind -r L resize-pane -R 5
bind x kill-pane
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'catppuccin/tmux'
set -g @catppuccin_flavour 'latte'
if "test -d ${tpm_dir}"
  run '${tpm_dir}/tpm'
endif
EOF
  write_user_file "${tmux_conf_path}" "${tmux_conf_content}"
  log_success "tmux 配置完成。"
  log_info "tmux 主题: Catppuccin Latte (浅色)"
  log_info "请在启动tmux后，按 'prefix + I' (大写I) 来安装TPM插件。"
  log_info "默认前缀是 Ctrl+b。所以是 Ctrl+b 然后按 Shift+i。"
  mark_completed "tmux_config"
}

# --- 步骤 9：安装 Miniconda ---
install_miniconda() {
  skip_if_completed "miniconda" && return
  log_step "为用户 ${TARGET_USER} 安装Miniconda"
  if run_as_user "command -v conda" &>/dev/null; then
    log_warning "conda 命令已在用户 ${TARGET_USER} 的PATH中找到，跳过Miniconda安装。"
    log_info "Conda 版本: $(run_as_user "conda --version 2>/dev/null || echo unknown")"
    mark_completed "miniconda"
    return
  fi
  local miniconda_install_dir="${TARGET_HOME}/miniconda3"
  if run_as_user "[ -d '${miniconda_install_dir}/bin' ] && [ -x '${miniconda_install_dir}/bin/conda' ]"; then
    log_warning "Miniconda 已安装在 ${miniconda_install_dir}，跳过下载和安装。"
    log_info "尝试为 zsh 和 bash 初始化 conda (如果尚未完成)..."
    run_as_user "'${miniconda_install_dir}/bin/conda' init zsh || true"
    run_as_user "'${miniconda_install_dir}/bin/conda' init bash || true"
    mark_completed "miniconda"
    return
  fi
  log_info "开始安装 Miniconda..."
  local arch installer_url temp_installer_path
  arch="$(uname -m)"
  case "${arch}" in
    x86_64)  installer_url="https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh" ;;
    aarch64) installer_url="https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-aarch64.sh" ;;
    *)       log_error "不支持的CPU架构进行Miniconda安装: ${arch}"; return 1 ;;
  esac
  temp_installer_path="$(mktemp --tmpdir miniconda_installer.XXXXXX.sh)"
  log_info "下载 Miniconda (${arch}) 安装脚本从 ${installer_url} ..."
  if ! curl --connect-timeout 15 --max-time 180 -fsSL "${installer_url}" -o "${temp_installer_path}"; then
    log_error "下载 Miniconda 安装脚本失败！"
    rm -f "${temp_installer_path}"
    return 1
  fi
  chmod +x "${temp_installer_path}"
  log_info "以用户 ${TARGET_USER} 身份执行 Miniconda 安装脚本 (安装到 ${miniconda_install_dir})..."
  if run_as_user "bash '${temp_installer_path}' -b -p '${miniconda_install_dir}'"; then
    log_info "Miniconda 安装程序执行完毕。"
    log_info "初始化 conda for zsh 和 bash..."
    run_as_user "'${miniconda_install_dir}/bin/conda' init zsh"
    run_as_user "'${miniconda_install_dir}/bin/conda' init bash"
    log_success "Miniconda 安装并为shell初始化完成。"
    log_info "请重新登录或 source ~/.bashrc / ~/.zshrc 使conda生效。"
  else
    log_error "Miniconda 安装失败。"
  fi
  rm -f "${temp_installer_path}"
  mark_completed "miniconda"
}

# --- Docker 相关函数 ---
get_docker_registry_mirrors_decision() {
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

generate_docker_daemon_json() {
  local effective_mirror_config
  effective_mirror_config=$(get_docker_registry_mirrors_decision)
  local registry_mirrors_json_array=""
  if [[ "${effective_mirror_config}" == "CN" ]]; then
    registry_mirrors_json_array=$(cat <<MIRRORS
        "https://docker.m.daocloud.io",
        "https://docker.1ms.run",
        "https://hub.fast360.xyz",
        "https://docker.xuanyuan.me/"
MIRRORS
)
    log_info "Docker daemon 将配置中国大陆镜像加速器。"
  else
    log_info "Docker daemon 将使用官方Docker Hub (不配置特定镜像加速器)。"
  fi
  local daemon_json_content="{\n"
  daemon_json_content+="    \"data-root\": \"/var/lib/docker\",\n"
  daemon_json_content+="    \"log-driver\": \"json-file\",\n"
  daemon_json_content+="    \"log-level\": \"warn\",\n"
  daemon_json_content+="    \"log-opts\": {\n"
  daemon_json_content+="        \"max-file\": \"3\",\n"
  daemon_json_content+="        \"max-size\": \"10m\"\n"
  daemon_json_content+="    },\n"
  daemon_json_content+="    \"max-concurrent-downloads\": 10,\n"
  daemon_json_content+="    \"max-concurrent-uploads\": 10"
  if [[ -n "${registry_mirrors_json_array}" ]]; then
    daemon_json_content+=",\n"
    daemon_json_content+="    \"registry-mirrors\": [\n"
    daemon_json_content+="        ${registry_mirrors_json_array}\n"
    daemon_json_content+="    ]"
  fi
  daemon_json_content+=",\n"
  daemon_json_content+="    \"exec-opts\": [\"native.cgroupdriver=systemd\"],\n"
  daemon_json_content+="    \"live-restore\": true,\n"
  daemon_json_content+="    \"storage-driver\": \"overlay2\"\n"
  daemon_json_content+="}"
  echo "${daemon_json_content}"
}

configure_docker_daemon() {
  log_info "配置Docker daemon.json..."
  ${SUDO_CMD} mkdir -p /etc/docker
  local daemon_json_content
  daemon_json_content=$(generate_docker_daemon_json)
  echo -e "${daemon_json_content}" | ${SUDO_CMD} tee /etc/docker/daemon.json >/dev/null
  log_success "Docker daemon.json 配置完成 (/etc/docker/daemon.json)。"
}

add_user_to_docker_group() {
  # 只有当目标用户不是root时，才将其添加到docker组
  if [[ "${TARGET_USER}" != "root" ]]; then
    if ! groups "${TARGET_USER}" | grep -qw docker; then
      log_info "将用户 ${TARGET_USER} 添加到 docker 组..."
      local usermod_cmd="usermod"
      if ! command -v usermod &>/dev/null && [[ -x "/usr/sbin/usermod" ]]; then
          usermod_cmd="/usr/sbin/usermod"
      elif ! command -v usermod &>/dev/null; then
          log_error "usermod 命令未找到，无法将用户添加到docker组。"
          return 1
      fi
      ${SUDO_CMD} "${usermod_cmd}" -aG docker "${TARGET_USER}" # 如果SUDO_CMD为空(当前是root),直接执行
      log_warning "用户 ${TARGET_USER} 已添加到 docker 组。需要重新登录或运行 'newgrp docker' 使更改生效。"
    else
      log_info "用户 ${TARGET_USER} 已在 docker 组中。"
    fi
  else
    log_info "目标用户是root，默认拥有Docker权限，无需添加到docker组。"
  fi
}

start_and_verify_docker_service() {
  log_info "启动并启用Docker服务..."
  ${SUDO_CMD} systemctl daemon-reload
  ${SUDO_CMD} systemctl enable docker
  ${SUDO_CMD} systemctl start docker
  sleep 3
  if ${SUDO_CMD} systemctl is-active --quiet docker; then
    log_success "Docker 服务已成功启动并运行。"
    local installed_version
    installed_version="$(${SUDO_CMD} docker --version 2>/dev/null || echo "无法获取版本信息")"
    log_info "已安装Docker版本: ${installed_version}"
    if ${SUDO_CMD} docker info >/dev/null 2>&1; then
      log_success "Docker (docker info) 运行测试通过。"
    else
      log_warning "Docker 服务已启动，但 'docker info' 执行失败。可能需要用户权限或配置问题。"
    fi
  else
    log_error "Docker 服务启动失败！请检查日志: sudo journalctl -u docker.service"
    return 1
  fi
  return 0
}

# --- 步骤 10：安装 Docker (APT方式) ---
install_docker_apt() {
  skip_if_completed "docker_install_apt" && return
  log_step "安装Docker (APT官方仓库方式)"
  if command -v docker &>/dev/null && ${SUDO_CMD} systemctl is-active --quiet docker 2>/dev/null; then
    local docker_version_info
    docker_version_info=$(${SUDO_CMD} docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
    log_warning "检测到Docker已安装并运行 (版本: ${docker_version_info})。跳过APT方式安装。"
    configure_docker_daemon
    add_user_to_docker_group
    mark_completed "docker_install_apt"
    return
  fi
  if ! check_iptables; then log_error "iptables检查或安装失败，Docker可能无法正常工作。"; return 1; fi
  log_info "卸载可能存在的旧版本Docker包..."
  for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do
    ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get remove -y "$pkg" 2>/dev/null || true
  done
  ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get autoremove -y 2>/dev/null || true
  log_info "安装必要的依赖包..."
  if ! ${SUDO_CMD} apt-get update -qq; then log_error "APT update失败"; return 1; fi
  if ! ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gnupg; then log_error "Docker依赖安装失败"; return 1; fi
  log_info "添加Docker官方GPG密钥..."
  ${SUDO_CMD} install -m 0755 -d /etc/apt/keyrings
  local docker_gpg_url="https://download.docker.com/linux/$(. /etc/os-release && echo "${ID}")/gpg"
  if ! ${SUDO_CMD} curl -fsSL "${docker_gpg_url}" -o /etc/apt/keyrings/docker.asc; then
    log_error "下载Docker GPG密钥失败！"
    return 1
  fi
  ${SUDO_CMD} chmod a+r /etc/apt/keyrings/docker.asc
  log_info "添加Docker APT软件仓库..."
  # shellcheck source=/dev/null
  . /etc/os-release
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${ID} \
    ${VERSION_CODENAME} stable" | \
    ${SUDO_CMD} tee /etc/apt/sources.list.d/docker.list > /dev/null
  log_info "更新APT包列表并安装Docker CE..."
  if ! ${SUDO_CMD} apt-get update -qq; then log_error "APT update失败"; return 1; fi
  if ! ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
    log_error "通过APT安装Docker CE失败！请检查错误信息。"
    return 1
  fi
  configure_docker_daemon
  add_user_to_docker_group
  if start_and_verify_docker_service; then
    log_success "Docker (APT方式) 安装和配置完成！"
    mark_completed "docker_install_apt"
  else
    log_error "Docker (APT方式) 服务未能成功启动。"
  fi
}

# --- 步骤 10：安装 Docker (二进制方式) ---
install_docker_binary() {
  skip_if_completed "docker_install_binary" && return
  log_step "安装Docker (二进制方式)"
  if command -v docker &>/dev/null && ${SUDO_CMD} systemctl is-active --quiet docker 2>/dev/null; then
    log_warning "检测到Docker已安装并运行。跳过二进制方式安装。"
    configure_docker_daemon
    add_user_to_docker_group
    mark_completed "docker_install_binary"
    return
  fi
  if ! check_iptables; then log_error "iptables检查或安装失败，Docker可能无法正常工作。"; return 1; fi
  local arch docker_target_version download_url cache_dir="/opt/dev-env-cache/docker"
  local docker_tgz_filename docker_tgz_path temp_extract_dir
  arch="$(uname -m)"
  case "${arch}" in
    x86_64)   arch="x86_64" ;;
    aarch64)  arch="aarch64" ;;
    armv7l)   arch="armhf" ;;
    *)        log_error "不支持的CPU架构进行Docker二进制安装: ${arch}"; return 1 ;;
  esac
  docker_target_version="${DOCKER_VERSION}"
  log_info "将安装Docker版本: ${docker_target_version} (基于全局设置或默认值)"
  if [[ ! "${docker_target_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    log_warning "Docker版本号格式 (${docker_target_version}) 可能不标准，但仍尝试下载..."
  fi
  docker_tgz_filename="docker-${docker_target_version}.tgz"
  download_url="https://download.docker.com/linux/static/stable/${arch}/${docker_tgz_filename}"
  ${SUDO_CMD} mkdir -p "${cache_dir}"
  docker_tgz_path="${cache_dir}/${docker_tgz_filename}"
  if [[ -f "${docker_tgz_path}" ]]; then
    log_info "发现缓存的Docker安装包: ${docker_tgz_path}。将使用此缓存。"
  else
    log_info "下载Docker (${docker_target_version} for ${arch}) 从: ${download_url}"
    local temp_download_path
    temp_download_path="$(mktemp --tmpdir docker_download.XXXXXX.tgz)"
    if ! curl --connect-timeout 15 --max-time 300 -fsSL "${download_url}" -o "${temp_download_path}"; then
      log_error "下载Docker二进制包失败！请检查版本号、架构和网络。"
      log_error "尝试的URL: ${download_url}"
      rm -f "${temp_download_path}"
      return 1
    fi
    log_info "下载成功，移动到缓存目录: ${docker_tgz_path}"
    ${SUDO_CMD} mv "${temp_download_path}" "${docker_tgz_path}"
    ${SUDO_CMD} chmod 644 "${docker_tgz_path}"
  fi
  temp_extract_dir="$(mktemp -d --tmpdir docker_extract.XXXXXX)"
  log_info "解压Docker二进制文件从 ${docker_tgz_path} 到 ${temp_extract_dir}..."
  if ! tar xzf "${docker_tgz_path}" -C "${temp_extract_dir}"; then
    log_error "解压Docker二进制包失败！文件可能已损坏。"
    log_warning "如果使用了缓存，请尝试删除 ${docker_tgz_path} 后重试。"
    rm -rf "${temp_extract_dir}"
    return 1
  fi
  log_info "安装Docker二进制文件到 /usr/local/bin/ ..."
  ${SUDO_CMD} cp -f "${temp_extract_dir}"/docker/* /usr/local/bin/
  ${SUDO_CMD} chmod +x /usr/local/bin/docker*
  rm -rf "${temp_extract_dir}"
  log_success "Docker ${docker_target_version} 二进制文件安装完成。"
  log_info "安装和配置containerd (作为Docker依赖)..."
  if ! command -v containerd &>/dev/null; then
    if ! ${SUDO_CMD} apt-get update -qq; then log_warning "containerd安装前apt update失败"; fi
    if ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y containerd.io; then
      log_success "containerd.io (通过APT) 安装成功。"
      ${SUDO_CMD} mkdir -p /etc/containerd
      if command -v containerd &>/dev/null; then # 确保containerd命令可用
        ${SUDO_CMD} containerd config default | ${SUDO_CMD} tee /etc/containerd/config.toml >/dev/null
      fi
    else
      log_error "通过APT安装containerd.io失败。Docker可能无法运行。"
      log_warning "请尝试手动安装containerd，或确保系统已提供。"
    fi
  else
    log_info "containerd 已存在。"
  fi
  configure_docker_daemon
  add_user_to_docker_group
  log_info "配置Docker systemd服务 (/etc/systemd/system/docker.service)..."
  local docker_service_content
  read -r -d '' docker_service_content <<EOF || true
[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com
After=network-online.target containerd.service
Wants=network-online.target
Requires=containerd.service

[Service]
Type=notify
ExecStart=/usr/local/bin/dockerd
ExecReload=/bin/kill -s HUP \$MAINPID
TimeoutSec=0
RestartSec=2
Restart=always
KillMode=process
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity

[Install]
WantedBy=multi-user.target
EOF
  echo "${docker_service_content}" | ${SUDO_CMD} tee /etc/systemd/system/docker.service > /dev/null
  if start_and_verify_docker_service; then
    log_success "Docker (二进制方式) 安装和配置完成！"
    mark_completed "docker_install_binary"
  else
    log_error "Docker (二进制方式) 服务未能成功启动。"
  fi
}

install_docker() {
  if [[ "${DOCKER_INSTALL_METHOD}" == "apt" ]]; then
    install_docker_apt
  elif [[ "${DOCKER_INSTALL_METHOD}" == "binary" ]]; then
    install_docker_binary
  else
    log_error "未知的Docker安装方式: ${DOCKER_INSTALL_METHOD}"
    log_info "请在脚本开始时选择 'apt' 或 'binary'。"
    return 1
  fi
}

# --- 步骤 11：安装 Docker Compose ---
install_docker_compose() {
  if [[ "${DOCKER_INSTALL_METHOD}" == "apt" ]]; then
    if ${SUDO_CMD} docker compose version &>/dev/null; then
      local compose_plugin_version
      compose_plugin_version=$(${SUDO_CMD} docker compose version --short 2>/dev/null || echo "unknown")
      log_success "Docker Compose (作为插件) 已通过APT与Docker一同安装 (版本: ${compose_plugin_version})。"
      mark_completed "docker_compose"
      return
    else
      log_warning "Docker通过APT安装，但 'docker compose' (插件) 未找到。"
      log_info "尝试通过APT单独安装 docker-compose-plugin..."
      if ! ${SUDO_CMD} apt-get update -qq; then log_warning "docker-compose-plugin安装前apt update失败"; fi
      if ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-plugin; then
          log_success "Docker Compose 插件安装成功。"
          mark_completed "docker_compose"
          return
      else
          log_warning "APT安装 docker-compose-plugin 失败。将尝试独立二进制安装。"
      fi
    fi
  fi
  skip_if_completed "docker_compose_standalone" && return
  log_step "安装Docker Compose (独立二进制)"
  if command -v docker-compose &>/dev/null; then
    local standalone_compose_version
    standalone_compose_version=$(docker-compose --version 2>/dev/null | awk '{print $NF}')
    log_warning "独立版 docker-compose 已存在 (版本: ${standalone_compose_version})，跳过安装。"
    mark_completed "docker_compose_standalone"
    return
  fi
  local arch compose_target_version download_url install_path="/usr/local/bin/docker-compose"
  local cache_dir="/opt/dev-env-cache/docker-compose"
  local compose_filename compose_cache_path
  arch="$(uname -m)"
  local arch_suffix # 重命名以避免与全局arch冲突
  case "${arch}" in
    x86_64)   arch_suffix="linux-x86_64" ;;
    aarch64)  arch_suffix="linux-aarch64" ;;
    armv7l)   arch_suffix="linux-armv7" ;;
    *)        log_error "不支持的CPU架构进行Docker Compose独立版安装: ${arch}"; return 1 ;;
  esac
  compose_target_version="${DOCKER_COMPOSE_VERSION}"
  log_info "将安装Docker Compose版本: ${compose_target_version}"
  if [[ ! "${compose_target_version}" =~ ^v ]]; then
    compose_target_version="v${compose_target_version}"
  fi
  compose_filename="docker-compose-${arch_suffix}"
  download_url="$(add_github_proxy "https://github.com/docker/compose/releases/download/${compose_target_version}/${compose_filename}")"
  ${SUDO_CMD} mkdir -p "${cache_dir}"
  compose_cache_path="${cache_dir}/docker-compose-${compose_target_version}-${arch_suffix}"
  if [[ -f "${compose_cache_path}" ]]; then
    log_info "发现缓存的Docker Compose: ${compose_cache_path}。"
  else
    log_info "下载Docker Compose (${compose_target_version} for ${arch_suffix}) 从: ${download_url}"
    local temp_download_compose
    temp_download_compose="$(mktemp --tmpdir docker_compose_dl.XXXXXX)"
    if ! curl --connect-timeout 15 --max-time 180 -fsSL "${download_url}" -o "${temp_download_compose}"; then
      log_error "下载Docker Compose失败！请检查版本、架构和网络。"
      log_error "尝试的URL: ${download_url}"
      rm -f "${temp_download_compose}"
      return 1
    fi
    log_info "下载成功，移动到缓存: ${compose_cache_path}"
    ${SUDO_CMD} mv "${temp_download_compose}" "${compose_cache_path}"
    ${SUDO_CMD} chmod 644 "${compose_cache_path}"
  fi
  log_info "安装Docker Compose到 ${install_path}..."
  ${SUDO_CMD} cp "${compose_cache_path}" "${install_path}"
  ${SUDO_CMD} chmod +x "${install_path}"
  if command -v docker-compose &>/dev/null; then
    local installed_compose_version
    installed_compose_version=$(docker-compose --version 2>/dev/null || echo "无法获取版本")
    log_success "Docker Compose (独立版) 安装完成！版本: ${installed_compose_version}"
    mark_completed "docker_compose_standalone"
  else
    log_error "Docker Compose (独立版) 安装后未找到命令。请检查安装过程。"
  fi
}

# --- 步骤 12：安装额外开发工具 (可选) ---
install_extra_tools() {
  if [[ "${INSTALL_EXTRA_TOOLS}" != "true" ]]; then
    log_info "根据用户选择，跳过额外开发工具的安装。"
    return
  fi
  skip_if_completed "extra_tools" && return
  log_step "安装额外开发工具"
  if ! ${SUDO_CMD} apt-get update -qq; then log_error "安装额外工具前apt update失败"; return 1; fi
  if ! command -v node &>/dev/null; then
    log_info "安装 Node.js LTS (通过 NodeSource)..."
    local nodesource_script_url="https://deb.nodesource.com/setup_lts.x"
    local temp_nodesource_script
    temp_nodesource_script="$(mktemp --tmpdir nodesource_setup.XXXXXX.sh)"
    if download_and_process_script "${nodesource_script_url}" "${temp_nodesource_script}" "false"; then
      if ${SUDO_CMD} bash "${temp_nodesource_script}"; then
        if ! ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs; then log_error "nodejs安装失败"; fi
        log_success "Node.js LTS 安装完成。版本: $(node -v 2>/dev/null || echo unknown), npm: $(npm -v 2>/dev/null || echo unknown)"
      else
        log_error "NodeSource脚本执行失败或nodejs安装失败。"
      fi
      rm -f "${temp_nodesource_script}"
    else
      log_error "下载NodeSource安装脚本失败。"
    fi
  else
    log_warning "Node.js 已安装 (版本: $(node -v 2>/dev/null || echo unknown))，跳过。"
  fi
  log_info "安装 Python3-pip, JDK (default), Go, Ruby, PHP, SQLite, yq..."
  local common_dev_tools=(
    python3-pip default-jdk golang-go ruby-full php-cli php-sqlite3 sqlite3 yq
  )
  if ! ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y "${common_dev_tools[@]}"; then
    log_warning "部分通用开发工具安装可能失败，请检查日志。"
  else
    log_success "Python3-pip, JDK, Go, Ruby, PHP, SQLite, yq 安装完成/已是最新。"
  fi
  log_info "安装数据库客户端: MySQL, PostgreSQL, Redis..."
  if ! ( ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y default-mysql-client || \
         ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-client || \
         ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-client ); then
    log_warning "MySQL/MariaDB 客户端安装失败。请根据您的系统手动安装。"
  else
    log_success "MySQL/MariaDB 客户端安装成功。"
  fi
  if ! ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql-client redis-tools; then log_warning "PostgreSQL/Redis客户端安装失败"; fi

  if ! command -v code &>/dev/null; then
    log_info "安装 Visual Studio Code..."
    log_info "尝试通过Microsoft APT仓库安装 VSCode..."
    if ! ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y wget gpg apt-transport-https; then log_error "VSCode依赖安装失败"; fi
    local vscode_gpg_key_url="https://packages.microsoft.com/keys/microsoft.asc"
    local vscode_gpg_keyring="/etc/apt/keyrings/packages.microsoft.gpg"
    wget -qO- "${vscode_gpg_key_url}" | gpg --dearmor | ${SUDO_CMD} tee "${vscode_gpg_keyring}" > /dev/null
    ${SUDO_CMD} chmod a+r "${vscode_gpg_keyring}"
    echo "deb [arch=amd64,arm64,armhf signed-by=${vscode_gpg_keyring}] https://packages.microsoft.com/repos/code stable main" | \
      ${SUDO_CMD} tee /etc/apt/sources.list.d/vscode.list > /dev/null
    if ${SUDO_CMD} apt-get update -qq && ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt-get install -y code; then
      log_success "Visual Studio Code (APT方式) 安装成功。"
    else
      log_warning "通过APT安装VSCode失败。清理VSCode的APT源配置..."
      ${SUDO_CMD} rm -f /etc/apt/sources.list.d/vscode.list "${vscode_gpg_keyring}" 2>/dev/null || true
      if command -v snap &>/dev/null; then
        log_info "APT方式失败，尝试通过 Snap 安装 VSCode (code --classic)..."
        if ${SUDO_CMD} snap install code --classic; then
          log_success "Visual Studio Code (Snap方式) 安装成功。"
        else
          log_error "通过Snap安装VSCode也失败。请尝试手动安装。"
        fi
      else
        log_error "APT安装VSCode失败，且snap不可用。请尝试手动安装。"
      fi
    fi
  else
    log_warning "Visual Studio Code (code命令) 已存在，跳过安装。"
  fi
  log_success "额外开发工具安装流程执行完毕。"
  mark_completed "extra_tools"
}

# --- 步骤 13：配置 Git ---
configure_git() {
  skip_if_completed "git_config" && return
  log_step "为用户 ${TARGET_USER} 配置Git全局设置"
  if ! command -v git &>/dev/null; then
    log_warning "Git命令未找到，跳过Git配置。请先安装Git。"
    return 1
  fi
  log_info "配置 Git 全局用户名和邮箱 (如果尚未设置)..."
  local current_git_name current_git_email
  current_git_name=$(run_as_user "git config --global user.name" 2>/dev/null || true)
  current_git_email=$(run_as_user "git config --global user.email" 2>/dev/null || true)
  if [[ -z "${current_git_name}" ]]; then
    read -rp "$(log_prompt "请输入您的 Git 用户名 (例如: Your Name, 直接回车跳过): ")" git_user_name_input
    if [[ -n "${git_user_name_input}" ]]; then
      run_as_user "git config --global user.name '${git_user_name_input}'"
      log_info "Git 全局用户名已设置为: ${git_user_name_input}"
    fi
  else
    log_info "Git 全局用户名已配置为: ${current_git_name}"
  fi
  if [[ -z "${current_git_email}" ]]; then
    read -rp "$(log_prompt "请输入您的 Git 邮箱 (例如: your.email@example.com, 直接回车跳过): ")" git_user_email_input
    if [[ -n "${git_user_email_input}" ]]; then
      run_as_user "git config --global user.email '${git_user_email_input}'"
      log_info "Git 全局邮箱已设置为: ${git_user_email_input}"
    fi
  else
    log_info "Git 全局邮箱已配置为: ${current_git_email}"
  fi
  log_info "配置其他 Git 全局选项 (默认分支main, pull使用rebase, core.editor vim)..."
  run_as_user "git config --global init.defaultBranch main"
  run_as_user "git config --global pull.rebase false"
  run_as_user "git config --global core.editor vim"
  log_success "Git 全局配置完成。"
  mark_completed "git_config"
}

# --- 步骤 14：最终用户目录和别名设置 ---
final_setup() {
  skip_if_completed "final_user_setup" && return
  log_step "为用户 ${TARGET_USER} 进行最终设置 (目录、别名)"
  log_info "创建常用开发目录: ~/Projects, ~/Scripts, ~/Downloads ..."
  create_user_dir "${TARGET_HOME}/Projects"
  create_user_dir "${TARGET_HOME}/Scripts"
  create_user_dir "${TARGET_HOME}/Downloads"
  local zshrc_file_path="${TARGET_HOME}/.zshrc"
  if [[ ! -f "${zshrc_file_path}" ]]; then
    log_warning "${zshrc_file_path} 未找到，正在创建一个基础版本。"
    run_as_user "touch '${zshrc_file_path}'"
  fi
  log_info "向 ${zshrc_file_path} 添加自定义别名 (如果不存在)..."
  if ! run_as_user "grep -q '# Custom Aliases Marker (dev-env-script)' '${zshrc_file_path}'" 2>/dev/null; then
    local custom_aliases_content
    read -r -d '' custom_aliases_content <<EOF || true

# Custom Aliases Marker (dev-env-script) - 请勿删除此行，用于脚本判断
alias ls='ls --color=auto'
alias ll='ls -alFh'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias mkdir='mkdir -pv'
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'
alias h='history'
alias c='clear'
alias path='echo -e \${PATH//:/\\n}'
alias df='df -h'
alias du='du -hcs'
alias update='${SUDO_CMD} apt update && ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt upgrade -y && ${SUDO_CMD} env DEBIAN_FRONTEND=noninteractive apt autoremove -y && ${SUDO_CMD} apt clean'
alias t='tmux new-session -A -s main'
alias ta='tmux attach -t'
alias tl='tmux ls'
alias v='vim'
alias vi='vim'
alias vimdiff='vim -d'
alias g='git'
alias gst='git status -sb'
alias ga='git add'
alias gaa='git add .'
alias gc='git commit -m'
alias gca='git commit -am'
alias gco='git checkout'
alias gcb='git checkout -b'
alias gb='git branch'
alias gp='git push'
alias gpf='git push --force-with-lease'
alias gpl='git pull'
alias glog="git log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit --date=relative"
alias gdiff='git diff'
alias gignore='echo -e ".DS_Store\nThumbs.db\nnode_modules/\n.vscode/\n__pycache__/\n*.pyc\n*.swp\n*~" >> .gitignore'
alias d='${SUDO_CMD} docker'
alias dc='${SUDO_CMD} docker compose'
alias dps='${SUDO_CMD} docker ps -a'
alias di='${SUDO_CMD} docker images'
alias drm='${SUDO_CMD} docker rm'
alias drmi='${SUDO_CMD} docker rmi'
alias dlogs='${SUDO_CMD} docker logs -f'
alias dexec='${SUDO_CMD} docker exec -it'
alias dstop='${SUDO_CMD} docker stop'
alias dstart='${SUDO_CMD} docker start'
alias dprune='${SUDO_CMD} docker system prune -af --volumes'
alias proj='cd ~/Projects'
alias scripts='cd ~/Scripts'
alias dl='cd ~/Downloads'
alias conf='cd ~/.config'
# End Custom Aliases Marker
EOF
    run_as_user "echo \"${custom_aliases_content}\" >> '${zshrc_file_path}'"
    log_info "自定义别名已添加到 ${zshrc_file_path}。"
  else
    log_warning "检测到自定义别名标记，跳过添加别名。"
  fi
  log_success "最终用户设置完成。"
  mark_completed "final_user_setup"
}

# ---- 显示完成摘要与后续步骤 ----
show_summary() {
  log_success "-----------------------------------------------------"
  log_success "=== Debian/Ubuntu 开发环境配置脚本执行完毕 ==="
  log_success "-----------------------------------------------------"
  local github_proxy_status docker_mirror_status apt_mirror_status
  local gh_proxy_url
  gh_proxy_url=$(get_github_proxy)
  if [[ -n "${gh_proxy_url}" ]]; then
    github_proxy_status="已启用 (${gh_proxy_url})"
  else
    github_proxy_status="未启用 (非中国大陆地区或已手动禁用)"
  fi
  local docker_mirror_decision
  docker_mirror_decision=$(get_docker_registry_mirrors_decision)
  if [[ "${docker_mirror_decision}" == "CN" ]]; then
    docker_mirror_status="已配置中国大陆镜像加速器"
  else
    docker_mirror_status="使用官方Docker Hub (未配置特定加速器)"
  fi
  if [[ "${IN_CHINA}" == "true" ]]; then
    apt_mirror_status="已配置阿里云APT镜像源 (或尝试配置)"
  else
    apt_mirror_status="使用系统默认/官方APT源"
  fi
  echo
  log_info "配置摘要:"
  echo "  目标用户:         ${TARGET_USER}"
  echo "  运行模式:         $( [[ "${IS_ROOT}" == "true" ]] && echo "Root模式 (为${TARGET_USER}配置)" || echo "普通用户模式 (${TARGET_USER})" )"
  echo "  地区检测信息:     ${IN_CHINA_AUTO_DETECTED_INFO}"
  echo "  最终地区设定:     IN_CHINA=${IN_CHINA}"
  echo "  GitHub代理:       ${github_proxy_status}"
  echo "  APT镜像源:        ${apt_mirror_status}"
  echo "  Docker安装方式:   ${DOCKER_INSTALL_METHOD}"
  echo "  Docker镜像源:     ${docker_mirror_status}"
  echo "  安装额外工具:     $( [[ "${INSTALL_EXTRA_TOOLS}" == "true" ]] && echo "是" || echo "否" )"
  echo
  log_info "已安装/配置的主要组件："
  echo "  • 系统PATH环境变量 (持久化到 /etc/profile.d/)"
  echo "  • Sudo权限 (为用户 ${TARGET_USER})"
  echo "  • SSH服务 (允许root登录, 密码认证)"
  echo "  • 用户SSH密钥对 (~/.ssh/id_rsa, 免密登录localhost)"
  echo "  • iptables (Docker依赖)"
  echo "  • Zsh + Oh My Zsh + Powerlevel10k 主题"
  echo "  • Vim (amix/vimrc 增强配置 + Catppuccin Latte主题)"
  echo "  • tmux (Catppuccin Latte主题, TPM管理插件)"
  echo "  • Miniconda (Python环境管理)"
  echo "  • Docker (${DOCKER_INSTALL_METHOD}方式)"
  echo "  • Docker Compose ($( [[ "${DOCKER_INSTALL_METHOD}" == "apt" ]] && echo "插件版" || echo "独立版" ))"
  if [[ "${INSTALL_EXTRA_TOOLS}" == "true" ]]; then
    echo "  • 额外开发工具 (Node.js, JDK, Go, Python-pip, VSCode等)"
  fi
  echo "  • Git (全局用户名、邮箱、默认行为)"
  echo "  • 常用开发目录 (~/Projects等) 及Zsh别名"
  echo
  log_warning "重要后续步骤："
  echo -e "  1. ${YELLOW}重新登录${NC}用户 ${TARGET_USER} 或 ${YELLOW}重启系统${NC} 以确保所有更改完全生效："
  echo "     - Zsh成为默认shell。"
  echo "     - Docker用户组权限 (非root用户无需sudo执行docker命令)。"
  echo "     - 新的PATH环境变量加载。"
  echo "     - Miniconda环境初始化。"
  echo -e "  2. ${YELLOW}Vim配置${NC}: 基于amix/vimrc的增强配置已安装，包含大量有用插件。"
  echo -e "     - 个人配置文件: ${GREEN}~/.vim_runtime/my_configs.vim${NC}"
  echo -e "     - 编辑个人配置: 在Vim中按 ${GREEN}<leader>ev${NC} (空格+e+v)"
  echo -e "     - 重载个人配置: 在Vim中按 ${GREEN}<leader>sv${NC} (空格+s+v)"
  echo "     - 主题: Catppuccin Latte (浅色)，可在my_configs.vim中修改flavour"
  echo -e "  3. ${YELLOW}tmux插件${NC}: 启动tmux后，按 ${GREEN}Ctrl+b${NC} 然后按 ${GREEN}I${NC} (大写i) 来安装TPM插件。"
  echo -e "  4. ${YELLOW}Powerlevel10k配置${NC}: 如果Zsh提示符不是您期望的样式，"
  echo -e "     可以在Zsh中运行 ${GREEN}p10k configure${NC} 来进行个性化配置。"
  echo -e "  5. ${YELLOW}检查各项工具版本${NC}：例如 'docker --version', 'docker compose version' (或 'docker-compose --version'),"
  echo "     'node -v', 'python --version', 'go version', 'code --version' 等。"
  echo -e "  6. ${YELLOW}Git配置${NC}: 如果之前跳过了Git用户名/邮箱设置，请手动配置："
  echo -e "     ${GREEN}git config --global user.name \"Your Name\"${NC}"
  echo -e "     ${GREEN}git config --global user.email \"you@example.com\"${NC}"
  echo
  log_info "脚本状态文件: $(get_status_file)"
  log_info "  如果需要重新运行部分或全部步骤，可以删除此文件或编辑它。"
  echo
  log_success "开发环境配置流程结束。祝您编码愉快！"
  log_success "-----------------------------------------------------"
}

# ---- 主流程控制与参数处理 ----
main() {
  case "${1:-}" in
    --clean|--reset)
      init_user_info
      local status_file_path
      status_file_path=$(get_status_file)
      if [[ -f "${status_file_path}" ]]; then
        if rm -f "${status_file_path}"; then
          log_success "状态文件已清理: ${status_file_path}"
        else
          log_error "清理状态文件 ${status_file_path} 失败。"
        fi
      else
        log_info "状态文件不存在，无需清理: ${status_file_path}"
      fi
      exit 0
      ;;
    --status)
      init_user_info
      local status_file_path
      status_file_path=$(get_status_file)
      if [[ -f "${status_file_path}" ]]; then
        log_info "已完成的配置步骤 (记录于 ${status_file_path}):"
        cat "${status_file_path}"
      else
        log_info "尚无已完成步骤的记录 (状态文件 ${status_file_path} 不存在)。"
      fi
      exit 0
      ;;
    -h|--help)
      cat <<HELP_EOF
${GREEN}Debian/Ubuntu 一键开发环境配置脚本 (增强版)${NC}
${YELLOW}用法:${NC}
  $0 [选项]
${YELLOW}选项:${NC}
  --clean, --reset    清理安装状态文件，以便重新执行所有步骤。
  --status            显示已完成的配置步骤。
  -h, --help          显示此帮助信息。
${YELLOW}环境变量 (用于自定义行为):${NC}
  ${CYAN}IN_CHINA${NC}               地区配置 (auto/true/false, 默认: auto)
  ${CYAN}GITHUB_PROXY${NC}           GitHub代理服务器URL (默认: https://ghfast.top)
  ${CYAN}DOCKER_VERSION${NC}        指定Docker版本 (二进制安装, 默认: ${DOCKER_VERSION})
  ${CYAN}DOCKER_COMPOSE_VERSION${NC} 指定Docker Compose版本 (二进制安装, 默认: ${DOCKER_COMPOSE_VERSION})
  ${CYAN}REGISTRY_MIRROR${NC}      Docker镜像源策略 (auto/CN/NONE, 默认: auto)
${YELLOW}脚本特性:${NC}
  • 自动用户检测与sudo配置 (允许为root用户配置)
  • 持久化PATH环境变量修复
  • SSH服务与用户密钥配置
  • ${GREEN}地区智能适配${NC} (APT源, GitHub代理, Docker镜像)
  • ${GREEN}Zsh + Oh My Zsh + Powerlevel10k${NC}
  • ${GREEN}增强版Vim配置${NC} (amix/vimrc + Catppuccin Latte)
  • ${GREEN}tmux配置${NC} (Catppuccin Latte, TPM)
  • Miniconda Python环境管理器
  • ${GREEN}灵活的Docker安装${NC} (APT方式或二进制方式)
  • 可选安装额外开发工具
  • Git全局配置辅助
  • ${GREEN}幂等性设计${NC} (可重复运行)
${YELLOW}使用示例:${NC}
  bash $0
  IN_CHINA=true bash $0
HELP_EOF
      exit 0
      ;;
  esac

  echo
  log_success "=== Debian/Ubuntu 开发环境配置脚本 (增强版) ==="
  echo

  detect_china_region
  log_info "脚本将基于以下配置运行:"
  log_info "  最终地区设定 (IN_CHINA): ${IN_CHINA} (${IN_CHINA_AUTO_DETECTED_INFO})"
  log_info "  GitHub代理将 $( [[ "$(get_github_proxy)" ]] && echo "启用 ($(get_github_proxy))" || echo "禁用" )"
  log_info "  Docker镜像源策略 (REGISTRY_MIRROR): ${REGISTRY_MIRROR} -> $(get_docker_registry_mirrors_decision)"
  log_info "  Docker版本 (二进制安装时使用): ${DOCKER_VERSION}"
  log_info "  Docker Compose版本 (二进制安装时使用): ${DOCKER_COMPOSE_VERSION}"
  echo

  init_user_info
  check_system

  if [[ -f "$(get_status_file)" ]]; then
    log_warning "检测到之前的配置记录。脚本将尝试跳过已完成的步骤。"
    log_info "已完成步骤列表 ($(get_status_file)):"
    cat "$(get_status_file)"
    echo
  fi

  read -rp "$(log_prompt "是否继续为用户 ${TARGET_USER} (家目录: ${TARGET_HOME}) 配置开发环境？(y/N): ")" confirm_start
  if [[ "${confirm_start,,}" != "y" ]]; then
    log_info "操作已取消。"
    exit 0
  fi

  configure_installation_options

  echo
  log_success "=== 开始执行配置步骤 ==="
  echo

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

  echo
  show_summary
}

# --- 脚本执行入口 ---
main "$@"
