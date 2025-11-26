#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import re
import json
import logging
import datetime
from typing import List, Dict, Tuple

class UFWManager:
    """UFW防火墙管理器"""

    def __init__(self, debug=False):
        self.debug = debug
        self.setup_logging()

    def setup_logging(self):
        """设置调试日志"""
        if self.debug:
            # 创建日志记录器
            self.logger = logging.getLogger('UFWManager')
            self.logger.setLevel(logging.DEBUG)

            # 创建文件处理器
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            log_file = f'AGENTS/ufw_debug_{timestamp}.log'

            try:
                file_handler = logging.FileHandler(log_file, encoding='utf-8')
                file_handler.setLevel(logging.DEBUG)

                # 创建格式化器
                formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
                file_handler.setFormatter(formatter)

                self.logger.addHandler(file_handler)
                self.logger.info("UFW管理器调试日志启动")
            except Exception as e:
                print(f"无法创建日志文件: {e}")

    def log_debug(self, message):
        """记录调试信息"""
        if self.debug and hasattr(self, 'logger'):
            self.logger.debug(message)
        elif self.debug:
            print(f"[DEBUG] {message}")

    def log_info(self, message):
        """记录信息"""
        if self.debug and hasattr(self, 'logger'):
            self.logger.info(message)
        elif self.debug:
            print(f"[INFO] {message}")

    def log_error(self, message):
        """记录错误"""
        if self.debug and hasattr(self, 'logger'):
            self.logger.error(message)
        elif self.debug:
            print(f"[ERROR] {message}")

    def run_command(self, command: str) -> Tuple[bool, str]:
        """执行shell命令"""
        self.log_debug(f"执行命令: {command}")

        try:
            self.log_debug("开始执行subprocess...")
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )

            # 记录详细结果
            self.log_debug(f"命令返回码: {result.returncode}")
            self.log_debug(f"标准输出: {result.stdout}")
            if result.stderr:
                self.log_debug(f"标准错误: {result.stderr}")

            success = result.returncode == 0
            output = result.stdout.strip()

            self.log_info(f"命令执行结果: {'成功' if success else '失败'}")
            self.log_info(f"输出内容长度: {len(output)} 字符")

            return success, output

        except subprocess.TimeoutExpired:
            error_msg = "命令执行超时"
            self.log_error(error_msg)
            return False, error_msg
        except subprocess.CalledProcessError as e:
            error_msg = f"命令执行失败: {e}"
            self.log_error(error_msg)
            self.log_error(f"返回码: {e.returncode}")
            self.log_error(f"输出: {e.output}")
            return False, error_msg
        except Exception as e:
            error_msg = f"未知错误: {e}"
            self.log_error(error_msg)
            return False, error_msg

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