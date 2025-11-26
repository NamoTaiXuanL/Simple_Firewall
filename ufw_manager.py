#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import re
import json
from typing import List, Dict, Tuple

class UFWManager:
    """UFW防火墙管理器"""

    def __init__(self):
        self.sudo_password = None

    def log(self, message):
        """直接在终端显示信息"""
        print(f"[UFW] {message}")

    def set_sudo_password(self, password):
        """设置sudo密码"""
        self.sudo_password = password
        print("[UFW] sudo密码已设置")

    def run_command(self, command: str) -> Tuple[bool, str]:
        """执行shell命令"""
        print(f"[UFW] 执行命令: {command}")

        try:
            # 如果需要sudo权限且已设置密码
            if command.startswith('sudo') and self.sudo_password:
                # 修改命令使用 -S 参数，并添加timeout
                modified_command = command.replace('sudo', 'sudo -S')
                print(f"[UFW] 修改后命令: {modified_command}")

                # 使用管道方式传递密码
                process = subprocess.run(
                    modified_command,
                    input=self.sudo_password + '\n',
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=15  # 减少超时时间
                )
                result = process
            else:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

            print(f"[UFW] 返回码: {result.returncode}")
            print(f"[UFW] 输出长度: {len(result.stdout)} 字符")
            if result.stdout:
                print(f"[UFW] 输出: {result.stdout[:200]}...")  # 只显示前200字符
            if result.stderr:
                print(f"[UFW] 错误: {result.stderr[:200]}...")

            success = result.returncode == 0
            output = result.stdout.strip()

            print(f"[UFW] 执行结果: {'成功' if success else '失败'}")
            return success, output

        except subprocess.TimeoutExpired:
            error_msg = f"命令执行超时: {command}"
            print(f"[UFW] {error_msg}")
            return False, error_msg
        except Exception as e:
            print(f"[UFW] 异常: {e}")
            return False, str(e)

    
    def get_status(self) -> Dict[str, any]:
        """获取防火墙状态"""
        success, output = self.run_command("sudo ufw status verbose")
        if not success:
            return {"active": False, "error": output}

        active = "Status: active" in output
        logging = "Logging: on" in output

        # 解析规则
        rules = []
        lines = output.split('\n')
        for line in lines:
            if line.strip() and not line.startswith('Status:') and not line.startswith('Logging:') and not line.startswith('Default:'):
                if 'ALLOW' in line or 'DENY' in line:
                    rules.append(line.strip())

        return {
            "active": active,
            "logging": logging,
            "rules": rules,
            "raw_output": output
        }

    def enable_firewall(self) -> Tuple[bool, str]:
        """启用防火墙"""
        return self.run_command("echo 'y' | sudo ufw enable")

    def disable_firewall(self) -> Tuple[bool, str]:
        """禁用防火墙"""
        return self.run_command("sudo ufw disable")

    def add_rule(self, rule: str) -> Tuple[bool, str]:
        """添加规则"""
        return self.run_command(f"sudo ufw {rule}")

    def delete_rule(self, rule_num: int) -> Tuple[bool, str]:
        """删除规则（按编号）"""
        return self.run_command(f"echo 'y' | sudo ufw delete {rule_num}")

    def delete_rule_by_content(self, rule: str) -> Tuple[bool, str]:
        """删除规则（按内容）"""
        return self.run_command(f"echo 'y' | sudo ufw delete {rule}")

    def get_rules_with_numbers(self) -> List[Dict[str, str]]:
        """获取带编号的规则列表"""
        success, output = self.run_command("sudo ufw status numbered")
        if not success:
            return []

        rules = []
        lines = output.split('\n')
        for line in lines:
            # 匹配规则格式: [ 1] 22/tcp                   ALLOW IN    Anywhere
            match = re.match(r'\[\s*(\d+)\]\s*(.+)', line.strip())
            if match:
                rule_num = match.group(1)
                rule_content = match.group(2).strip()
                rules.append({
                    "number": rule_num,
                    "content": rule_content
                })

        return rules

    def reset_firewall(self) -> Tuple[bool, str]:
        """重置防火墙"""
        return self.run_command("echo 'y' | sudo ufw reset")

    def set_default_policy(self, policy: str) -> Tuple[bool, str]:
        """设置默认策略 (allow/deny/reject)"""
        if policy not in ['allow', 'deny', 'reject']:
            return False, "无效的策略"
        return self.run_command(f"sudo ufw default {policy}")

    def get_log_entries(self, lines: int = 50) -> List[str]:
        """获取日志条目"""
        success, output = self.run_command(f"sudo tail -n {lines} /var/log/ufw.log")
        if not success:
            return []
        return output.split('\n') if output else []

    def get_all_listening_programs(self) -> List[Dict[str, str]]:
        """获取所有监听端口的程序"""
        print("[UFW] 获取所有监听端口的程序...")

        success, output = self.run_command("ss -tulnp")
        if not success:
            return []

        programs = []
        lines = output.split('\n')

        for line in lines:
            if 'LISTEN' in line or ('users:' in line and ('tcp' in line or 'udp' in line)):
                try:
                    # 新版本ss格式: users:(("program",pid=123,fd=4))
                    if 'users:' in line:
                        # 提取程序信息
                        import re
                        match = re.search(r'users:\(\("([^"]+)",pid=(\d+),', line)
                        if match:
                            program_name = match.group(1)
                            pid = match.group(2)

                            # 提取端口信息
                            port_match = re.search(r'(\d+\.\d+\.\d+\.\d+|[^:]+):(\d+)', line)
                            if port_match:
                                address = port_match.group(1)
                                port = port_match.group(2)

                                # 获取协议
                                protocol = 'tcp' if 'tcp' in line else 'udp'

                                programs.append({
                                    'name': program_name,
                                    'pid': pid,
                                    'port': port,
                                    'protocol': protocol,
                                    'address': address + ':' + port
                                })
                    else:
                        # 旧格式解析
                        parts = line.split()
                        if len(parts) >= 6:
                            protocol = parts[0]
                            local_addr = parts[4]
                            program_info = parts[-1]

                            # 解析端口
                            port = ""
                            if ':' in local_addr:
                                port = local_addr.split(':')[-1]

                            # 解析程序名
                            program_name = ""
                            pid = ""
                            if program_info and '/' in program_info:
                                pid, program_name = program_info.split('/', 1)

                            if port and program_name and port.isdigit():
                                programs.append({
                                    'name': program_name,
                                    'pid': pid,
                                    'port': port,
                                    'protocol': protocol,
                                    'address': local_addr
                                })
                except Exception as e:
                    print(f"[UFW] 解析行失败: {line}, 错误: {e}")
                    continue

        # 去重，相同程序+端口只显示一个
        unique_programs = []
        seen = set()
        for prog in programs:
            key = f"{prog['name']}:{prog['port']}"
            if key not in seen:
                seen.add(key)
                unique_programs.append(prog)

        print(f"[UFW] 找到 {len(unique_programs)} 个程序")
        return unique_programs

    def allow_program_by_port(self, port: str, protocol: str = "tcp") -> Tuple[bool, str]:
        """为指定端口添加允许规则"""
        rule = f"allow {port}/{protocol}"
        return self.run_command(f"sudo ufw {rule}")