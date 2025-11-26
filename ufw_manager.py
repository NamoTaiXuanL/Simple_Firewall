#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import re
import json
from typing import List, Dict, Tuple

class UFWManager:
    """UFW防火墙管理器"""

    def __init__(self):
        pass

    def log(self, message):
        """直接在终端显示信息"""
        print(f"[UFW] {message}")

    def run_command(self, command: str) -> Tuple[bool, str]:
        """执行shell命令"""
        print(f"[UFW] 执行命令: {command}")

        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )

            print(f"[UFW] 返回码: {result.returncode}")
            print(f"[UFW] 输出: {result.stdout}")
            if result.stderr:
                print(f"[UFW] 错误: {result.stderr}")

            success = result.returncode == 0
            output = result.stdout.strip()

            print(f"[UFW] 执行结果: {'成功' if success else '失败'}")
            return success, output

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