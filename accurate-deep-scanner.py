#!/usr/bin/env python3
"""
Accurate Cyber Defense Penetration Testing Tool
Red-themed interface with Telegram integration
"""

import argparse
import asyncio
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    import requests
    from telegram import Update
    from telegram.ext import (
        Application,
        CommandHandler,
        ContextTypes,
        MessageHandler,
        filters,
    )
    import scapy.all as scapy
    from colorama import Fore, Style, init
except ImportError:
    print("Please install required packages: pip install python-telegram-bot scapy colorama requests")
    sys.exit(1)

# Initialize colorama for colored output
init(autoreset=True)

# Red theme color codes
RED = Fore.RED
LIGHT_RED = Fore.LIGHTRED_EX
DARK_RED = "\033[38;5;88m"  # Custom dark red
RESET = Style.RESET_ALL
BOLD = Style.BRIGHT

# Configuration
CONFIG_FILE = "cyber_tool_config.json"
DEFAULT_CONFIG = {
    "monitored_ips": [],
    "telegram_token": "",
    "telegram_chat_id": "",
    "scan_timeout": 1,
    "max_ping_count": 4,
    "deep_scan_batch_size": 1000,
}

class CyberSecurityTool:
    def __init__(self):
        self.config = self.load_config()
        self.monitoring = False
        self.monitored_ips = set(self.config.get("monitored_ips", []))
        self.monitoring_thread = None
        self.telegram_app = None
        self.telegram_initialized = False
        
    def load_config(self) -> Dict:
        """Load configuration from file"""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return DEFAULT_CONFIG.copy()
        return DEFAULT_CONFIG.copy()
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except IOError:
            self.print_error("Failed to save configuration")
            return False
    
    def print_banner(self):
        """Display the tool banner"""
        banner = f"""
        {RED}{BOLD}
        ╔══════════════════════════════════════════════════════════════╗
        ║                                                              ║
        ║            ACCURATE CYBER DEFENSE                            ║
        ║                                                              ║
        ║        Advanced Cyber Drill Penetration Testing              ║
                 https://github.com/Accurate-Cyber-Defense              ╕
        
        ╚══════════════════════════════════════════════════════════════╝
        {RESET}
        """
        print(banner)
    
    def print_error(self, message: str):
        """Print error message in red theme"""
        print(f"{RED}[!] ERROR: {message}{RESET}")
    
    def print_success(self, message: str):
        """Print success message in red theme"""
        print(f"{LIGHT_RED}[+] {message}{RESET}")
    
    def print_info(self, message: str):
        """Print info message in red theme"""
        print(f"{DARK_RED}[*] {message}{RESET}")
    
    def print_warning(self, message: str):
        """Print warning message in yellow theme"""
        print(f"{Fore.YELLOW}[!] WARNING: {message}{RESET}")
    
    def print_help(self):
        """Display help information"""
        help_text = f"""
        {RED}{BOLD}Available Commands:{RESET}
        
        {LIGHT_RED}help{RESET}                 - Show this help message
        {LIGHT_RED}ping <IP>{RESET}            - Ping an IP address
        {LIGHT_RED}start monitoring <IP>{RESET} - Start monitoring an IP address
        {LIGHT_RED}stop{RESET}                 - Stop monitoring
        {LIGHT_RED}exit{RESET}                 - Exit the program
        {LIGHT_RED}clear{RESET}                - Clear the screen
        {LIGHT_RED}view{RESET}                 - View monitored IPs
        {LIGHT_RED}status{RESET}               - Show monitoring status
        {LIGHT_RED}add ip <IP>{RESET}          - Add IP to monitoring list
        {LIGHT_RED}remove ip <IP>{RESET}       - Remove IP from monitoring list
        {LIGHT_RED}config telegram token <TOKEN>{RESET} - Set Telegram bot token
        {LIGHT_RED}config telegram chat_id <ID>{RESET} - Set Telegram chat ID
        {LIGHT_RED}test telegram connection{RESET} - Test Telegram bot connection
        {LIGHT_RED}udptraceroute <IP>{RESET}   - Perform UDP traceroute
        {LIGHT_RED}tcptraceroute <IP>{RESET}   - Perform TCP traceroute
        {LIGHT_RED}scan <IP>{RESET}            - Scan IP for open ports
        {LIGHT_RED}deep scan <IP>{RESET}       - Deep scan IP (ports 1-65535)
        
        {RED}{BOLD}Telegram Commands:{RESET}
        
        {LIGHT_RED}/ping_ip <IP>{RESET}        - Ping an IP address
        {LIGHT_RED}/scan_ip <IP>{RESET}        - Scan IP for open ports
        {LIGHT_RED}/traceroute <IP>{RESET}     - Perform traceroute
        {LIGHT_RED}/view{RESET}                - View monitored IPs
        {LIGHT_RED}/help{RESET}                - Show help
        {LIGHT_RED}/deep_scan <IP>{RESET}      - Deep scan IP
        {LIGHT_RED}/exit{RESET}                - Exit the program
        {LIGHT_RED}/test_connection{RESET}     - Test Telegram connection
        """
        print(help_text)
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
    
    def validate_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def ping_ip(self, ip: str, count: int = 4) -> Tuple[bool, str]:
        """Ping an IP address"""
        if not self.validate_ip(ip):
            return False, "Invalid IP address"
        
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, str(count), ip]
        
        try:
            output = subprocess.run(command, capture_output=True, text=True, timeout=10)
            if output.returncode == 0:
                return True, output.stdout
            else:
                return False, output.stderr if output.stderr else "Ping failed"
        except subprocess.TimeoutExpired:
            return False, "Ping timed out"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def scan_ip(self, ip: str, ports: List[int] = None, timeout: float = 1.0) -> Dict[int, str]:
        """Scan IP for open ports"""
        if not self.validate_ip(ip):
            return {"error": "Invalid IP address"}
        
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        open_ports = {}
        
        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except OSError:
                            service = "unknown"
                        open_ports[port] = service
            except Exception:
                pass
        
        threads = []
        for port in ports:
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join(timeout=len(ports) * timeout / 10)
        
        return open_ports
    
    def deep_scan_ip(self, ip: str, batch_size: int = 1000, timeout: float = 0.5) -> Dict[int, str]:
        """Deep scan IP (ports 1-65535)"""
        if not self.validate_ip(ip):
            return {"error": "Invalid IP address"}
        
        open_ports = {}
        total_ports = 65535
        batches = total_ports // batch_size + (1 if total_ports % batch_size != 0 else 0)
        
        self.print_info(f"Starting deep scan on {ip} (1-65535)")
        
        for batch in range(batches):
            start_port = batch * batch_size + 1
            end_port = min((batch + 1) * batch_size, total_ports)
            self.print_info(f"Scanning ports {start_port} to {end_port}")
            
            ports = list(range(start_port, end_port + 1))
            batch_results = self.scan_ip(ip, ports, timeout)
            
            if "error" in batch_results:
                return batch_results
            
            open_ports.update(batch_results)
            
            # Small delay to avoid overwhelming the system
            time.sleep(0.1)
        
        return open_ports
    
    def traceroute(self, ip: str, protocol: str = "udp") -> List[Dict]:
        """Perform traceroute to an IP"""
        if not self.validate_ip(ip):
            return [{"error": "Invalid IP address"}]
        
        try:
            if protocol.lower() == "udp":
                result = subprocess.run(
                    ["traceroute", "-n", ip],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            else:
                result = subprocess.run(
                    ["traceroute", "-T", "-n", ip],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            
            if result.returncode == 0:
                lines = result.stdout.split("\n")
                hops = []
                for line in lines[1:]:  # Skip the first line
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            hop = {
                                "hop": parts[0],
                                "ip": parts[1],
                                "times": parts[2:] if len(parts) > 2 else []
                            }
                            hops.append(hop)
                return hops
            else:
                return [{"error": result.stderr}]
        except subprocess.TimeoutExpired:
            return [{"error": "Traceroute timed out"}]
        except FileNotFoundError:
            return [{"error": "Traceroute command not found"}]
        except Exception as e:
            return [{"error": f"Error: {str(e)}"}]
    
    def start_monitoring(self, ip: str = None):
        """Start monitoring IP addresses"""
        if ip:
            if not self.validate_ip(ip):
                self.print_error("Invalid IP address")
                return False
            
            if ip not in self.monitored_ips:
                self.monitored_ips.add(ip)
                self.config["monitored_ips"] = list(self.monitored_ips)
                self.save_config()
        
        if not self.monitored_ips:
            self.print_error("No IP addresses to monitor")
            return False
        
        if self.monitoring:
            self.print_info("Monitoring is already running")
            return True
        
        self.monitoring = True
        self.monitoring_thread = threading.Thread(target=self.monitor_ips)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        self.print_success(f"Started monitoring {len(self.monitored_ips)} IP addresses")
        return True
    
    def stop_monitoring(self):
        """Stop monitoring IP addresses"""
        if not self.monitoring:
            self.print_info("Monitoring is not running")
            return False
        
        self.monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        self.print_success("Stopped monitoring")
        return True
    
    def monitor_ips(self):
        """Monitor IP addresses for changes in status"""
        previous_status = {}
        
        while self.monitoring:
            current_status = {}
            
            for ip in list(self.monitored_ips):
                success, _ = self.ping_ip(ip, count=1)
                current_status[ip] = success
                
                if ip in previous_status and previous_status[ip] != success:
                    status = "up" if success else "down"
                    message = f"Status change: {ip} is {status}"
                    self.print_info(message)
                    
                    # Send notification via Telegram if configured
                    if self.telegram_initialized and self.config.get("telegram_chat_id"):
                        asyncio.run(
                            self.send_telegram_message(
                                self.config["telegram_chat_id"],
                                message
                            )
                        )
            
            previous_status = current_status
            time.sleep(60)  # Check every minute
    
    def add_ip(self, ip: str) -> bool:
        """Add IP to monitoring list"""
        if not self.validate_ip(ip):
            self.print_error("Invalid IP address")
            return False
        
        if ip in self.monitored_ips:
            self.print_info(f"{ip} is already in the monitoring list")
            return True
        
        self.monitored_ips.add(ip)
        self.config["monitored_ips"] = list(self.monitored_ips)
        self.save_config()
        self.print_success(f"Added {ip} to monitoring list")
        return True
    
    def remove_ip(self, ip: str) -> bool:
        """Remove IP from monitoring list"""
        if not self.validate_ip(ip):
            self.print_error("Invalid IP address")
            return False
        
        if ip not in self.monitored_ips:
            self.print_info(f"{ip} is not in the monitoring list")
            return True
        
        self.monitored_ips.remove(ip)
        self.config["monitored_ips"] = list(self.monitored_ips)
        self.save_config()
        self.print_success(f"Removed {ip} from monitoring list")
        return True
    
    def config_telegram_token(self, token: str) -> bool:
        """Set Telegram bot token"""
        if not token:
            self.print_error("Token cannot be empty")
            return False
        
        self.config["telegram_token"] = token
        self.save_config()
        self.print_success("Telegram token configured")
        
        # Initialize Telegram bot if chat ID is also configured
        if self.config.get("telegram_chat_id"):
            self.initialize_telegram()
        
        return True
    
    def config_telegram_chat_id(self, chat_id: str) -> bool:
        """Set Telegram chat ID"""
        if not chat_id:
            self.print_error("Chat ID cannot be empty")
            return False
        
        self.config["telegram_chat_id"] = chat_id
        self.save_config()
        self.print_success("Telegram chat ID configured")
        
        # Initialize Telegram bot if token is also configured
        if self.config.get("telegram_token"):
            self.initialize_telegram()
        
        return True
    
    def test_telegram_connection(self) -> bool:
        """Test Telegram bot connection"""
        if not self.config.get("telegram_token"):
            self.print_error("Telegram token not configured")
            return False
        
        if not self.config.get("telegram_chat_id"):
            self.print_error("Telegram chat ID not configured")
            return False
        
        if not self.telegram_initialized:
            self.print_warning("Telegram bot not initialized. Initializing now...")
            if not self.initialize_telegram():
                self.print_error("Failed to initialize Telegram bot")
                return False
        
        try:
            # Test by getting bot info
            bot_info = asyncio.run(self.telegram_app.bot.get_me())
            self.print_success(f"Connected to Telegram bot: @{bot_info.username}")
            
            # Test by sending a message
            test_message = "🔌 Cyber Security Tool - Connection Test Successful! ✅"
            success = asyncio.run(
                self.send_telegram_message(
                    self.config["telegram_chat_id"],
                    test_message
                )
            )
            
            if success:
                self.print_success("Test message sent successfully to Telegram")
                return True
            else:
                self.print_error("Failed to send test message to Telegram")
                return False
                
        except Exception as e:
            self.print_error(f"Telegram connection test failed: {str(e)}")
            return False
    
    def initialize_telegram(self):
        """Initialize Telegram bot"""
        if not self.config.get("telegram_token") or not self.config.get("telegram_chat_id"):
            self.print_error("Telegram token or chat ID not configured")
            return False
        
        try:
            self.telegram_app = (
                Application.builder()
                .token(self.config["telegram_token"])
                .build()
            )
            
            # Add handlers
            self.telegram_app.add_handler(CommandHandler("ping_ip", self.telegram_ping_ip))
            self.telegram_app.add_handler(CommandHandler("scan_ip", self.telegram_scan_ip))
            self.telegram_app.add_handler(CommandHandler("traceroute", self.telegram_traceroute))
            self.telegram_app.add_handler(CommandHandler("view", self.telegram_view))
            self.telegram_app.add_handler(CommandHandler("help", self.telegram_help))
            self.telegram_app.add_handler(CommandHandler("deep_scan", self.telegram_deep_scan))
            self.telegram_app.add_handler(CommandHandler("exit", self.telegram_exit))
            self.telegram_app.add_handler(CommandHandler("test_connection", self.telegram_test_connection))
            self.telegram_app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.telegram_unknown))
            
            self.telegram_initialized = True
            self.print_success("Telegram bot initialized")
            return True
        except Exception as e:
            self.print_error(f"Failed to initialize Telegram bot: {str(e)}")
            return False
    
    async def send_telegram_message(self, chat_id: str, message: str):
        """Send message via Telegram"""
        if not self.telegram_initialized:
            self.print_error("Telegram bot not initialized")
            return False
        
        try:
            await self.telegram_app.bot.send_message(chat_id=chat_id, text=message)
            return True
        except Exception as e:
            self.print_error(f"Failed to send Telegram message: {str(e)}")
            return False
    
    async def telegram_ping_ip(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle Telegram /ping_ip command"""
        if not self.telegram_initialized:
            await update.message.reply_text("Telegram bot not initialized")
            return
        
        if not context.args:
            await update.message.reply_text("Usage: /ping_ip <IP>")
            return
        
        ip = context.args[0]
        success, result = self.ping_ip(ip)
        
        if success:
            await update.message.reply_text(f"Ping to {ip} successful:\n{result}")
        else:
            await update.message.reply_text(f"Ping to {ip} failed:\n{result}")
    
    async def telegram_scan_ip(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle Telegram /scan_ip command"""
        if not self.telegram_initialized:
            await update.message.reply_text("Telegram bot not initialized")
            return
        
        if not context.args:
            await update.message.reply_text("Usage: /scan_ip <IP>")
            return
        
        ip = context.args[0]
        open_ports = self.scan_ip(ip)
        
        if "error" in open_ports:
            await update.message.reply_text(f"Scan failed: {open_ports['error']}")
            return
        
        if not open_ports:
            await update.message.reply_text(f"No open ports found on {ip}")
            return
        
        response = f"Open ports on {ip}:\n"
        for port, service in open_ports.items():
            response += f"Port {port} ({service})\n"
        
        await update.message.reply_text(response)
    
    async def telegram_traceroute(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle Telegram /traceroute command"""
        if not self.telegram_initialized:
            await update.message.reply_text("Telegram bot not initialized")
            return
        
        if not context.args:
            await update.message.reply_text("Usage: /traceroute <IP> [udp|tcp]")
            return
        
        ip = context.args[0]
        protocol = "udp"
        if len(context.args) > 1:
            protocol = context.args[1].lower()
            if protocol not in ["udp", "tcp"]:
                await update.message.reply_text("Protocol must be 'udp' or 'tcp'")
                return
        
        hops = self.traceroute(ip, protocol)
        
        if "error" in hops[0]:
            await update.message.reply_text(f"Traceroute failed: {hops[0]['error']}")
            return
        
        response = f"Traceroute to {ip} ({protocol}):\n"
        for hop in hops:
            if "hop" in hop and "ip" in hop:
                response += f"{hop['hop']} {hop['ip']} {' '.join(hop.get('times', []))}\n"
        
        await update.message.reply_text(response)
    
    async def telegram_view(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle Telegram /view command"""
        if not self.telegram_initialized:
            await update.message.reply_text("Telegram bot not initialized")
            return
        
        if not self.monitored_ips:
            await update.message.reply_text("No IP addresses being monitored")
            return
        
        response = "Monitored IP addresses:\n"
        for ip in self.monitored_ips:
            response += f"- {ip}\n"
        
        await update.message.reply_text(response)
    
    async def telegram_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle Telegram /help command"""
        if not self.telegram_initialized:
            await update.message.reply_text("Telegram bot not initialized")
            return
        
        help_text = """
        Available Telegram Commands:
        
        /ping_ip <IP> - Ping an IP address
        /scan_ip <IP> - Scan IP for open ports
        /traceroute <IP> [udp|tcp] - Perform traceroute
        /view - View monitored IPs
        /help - Show this help
        /deep_scan <IP> - Deep scan IP (ports 1-65535)
        /exit - Exit the program
        /test_connection - Test Telegram connection
        """
        
        await update.message.reply_text(help_text)
    
    async def telegram_deep_scan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle Telegram /deep_scan command"""
        if not self.telegram_initialized:
            await update.message.reply_text("Telegram bot not initialized")
            return
        
        if not context.args:
            await update.message.reply_text("Usage: /deep_scan <IP>")
            return
        
        ip = context.args[0]
        await update.message.reply_text(f"Starting deep scan on {ip}. This may take a while...")
        
        open_ports = self.deep_scan_ip(ip)
        
        if "error" in open_ports:
            await update.message.reply_text(f"Deep scan failed: {open_ports['error']}")
            return
        
        if not open_ports:
            await update.message.reply_text(f"No open ports found on {ip}")
            return
        
        response = f"Open ports on {ip} (deep scan):\n"
        for port, service in open_ports.items():
            response += f"Port {port} ({service})\n"
        
        await update.message.reply_text(response)
    
    async def telegram_test_connection(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle Telegram /test_connection command"""
        if not self.telegram_initialized:
            await update.message.reply_text("Telegram bot not initialized")
            return
        
        await update.message.reply_text("Testing Telegram connection...")
        
        if self.test_telegram_connection():
            await update.message.reply_text("✅ Telegram connection test successful!")
        else:
            await update.message.reply_text("❌ Telegram connection test failed!")
    
    async def telegram_exit(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle Telegram /exit command"""
        if not self.telegram_initialized:
            await update.message.reply_text("Telegram bot not initialized")
            return
        
        await update.message.reply_text("Exiting...")
        self.stop_monitoring()
        os._exit(0)
    
    async def telegram_unknown(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle unknown Telegram commands"""
        await update.message.reply_text("Unknown command. Use /help to see available commands.")
    
    def run_telegram_bot(self):
        """Run Telegram bot in a separate thread"""
        if not self.telegram_initialized:
            self.print_error("Telegram bot not initialized")
            return False
        
        try:
            self.print_info("Starting Telegram bot...")
            self.telegram_app.run_polling()
            return True
        except Exception as e:
            self.print_error(f"Failed to start Telegram bot: {str(e)}")
            return False
    
    def start_telegram_bot(self):
        """Start Telegram bot in a separate thread"""
        if not self.telegram_initialized:
            self.print_error("Telegram bot not initialized")
            return False
        
        self.telegram_thread = threading.Thread(target=self.run_telegram_bot)
        self.telegram_thread.daemon = True
        self.telegram_thread.start()
        self.print_success("Telegram bot started")
        return True
    
    def process_command(self, command: str) -> bool:
        """Process a command from the console"""
        parts = command.strip().split()
        if not parts:
            return True
        
        cmd = parts[0].lower()
        
        if cmd == "help":
            self.print_help()
        
        elif cmd == "ping":
            if len(parts) < 2:
                self.print_error("Usage: ping <IP>")
            else:
                ip = parts[1]
                success, result = self.ping_ip(ip)
                if success:
                    self.print_success(f"Ping to {ip} successful:\n{result}")
                else:
                    self.print_error(f"Ping to {ip} failed:\n{result}")
        
        elif cmd == "start":
            if len(parts) < 2:
                self.print_error("Usage: start monitoring <IP>")
            elif parts[1].lower() == "monitoring":
                ip = parts[2] if len(parts) > 2 else None
                self.start_monitoring(ip)
            else:
                self.print_error("Unknown start command")
        
        elif cmd == "stop":
            if len(parts) > 1 and parts[1].lower() == "monitoring":
                self.stop_monitoring()
            else:
                self.print_error("Usage: stop monitoring")
        
        elif cmd == "exit":
            self.stop_monitoring()
            return False
        
        elif cmd == "clear":
            self.clear_screen()
        
        elif cmd == "view":
            if not self.monitored_ips:
                self.print_info("No IP addresses being monitored")
            else:
                self.print_info("Monitored IP addresses:")
                for ip in self.monitored_ips:
                    print(f"  {ip}")
        
        elif cmd == "status":
            if self.monitoring:
                self.print_info("Monitoring is active")
                self.print_info(f"Monitoring {len(self.monitored_ips)} IP addresses:")
                for ip in self.monitored_ips:
                    print(f"  {ip}")
            else:
                self.print_info("Monitoring is not active")
        
        elif cmd == "add":
            if len(parts) < 3:
                self.print_error("Usage: add ip <IP>")
            elif parts[1].lower() == "ip":
                ip = parts[2]
                self.add_ip(ip)
            else:
                self.print_error("Usage: add ip <IP>")
        
        elif cmd == "remove":
            if len(parts) < 3:
                self.print_error("Usage: remove ip <IP>")
            elif parts[1].lower() == "ip":
                ip = parts[2]
                self.remove_ip(ip)
            else:
                self.print_error("Usage: remove ip <IP>")
        
        elif cmd == "config":
            if len(parts) < 4:
                self.print_error("Usage: config telegram token <TOKEN> or config telegram chat_id <ID>")
            elif parts[1].lower() == "telegram":
                if parts[2].lower() == "token":
                    token = parts[3]
                    self.config_telegram_token(token)
                elif parts[2].lower() == "chat_id":
                    chat_id = parts[3]
                    self.config_telegram_chat_id(chat_id)
                else:
                    self.print_error("Usage: config telegram token <TOKEN> or config telegram chat_id <ID>")
            else:
                self.print_error("Usage: config telegram token <TOKEN> or config telegram chat_id <ID>")
        
        elif cmd == "test":
            if len(parts) < 3:
                self.print_error("Usage: test telegram connection")
            elif parts[1].lower() == "telegram" and parts[2].lower() == "connection":
                self.test_telegram_connection()
            else:
                self.print_error("Usage: test telegram connection")
        
        elif cmd == "udptraceroute":
            if len(parts) < 2:
                self.print_error("Usage: udptraceroute <IP>")
            else:
                ip = parts[1]
                hops = self.traceroute(ip, "udp")
                if "error" in hops[0]:
                    self.print_error(f"UDP traceroute failed: {hops[0]['error']}")
                else:
                    self.print_info(f"UDP traceroute to {ip}:")
                    for hop in hops:
                        if "hop" in hop and "ip" in hop:
                            print(f"  {hop['hop']} {hop['ip']} {' '.join(hop.get('times', []))}")
        
        elif cmd == "tcptraceroute":
            if len(parts) < 2:
                self.print_error("Usage: tcptraceroute <IP>")
            else:
                ip = parts[1]
                hops = self.traceroute(ip, "tcp")
                if "error" in hops[0]:
                    self.print_error(f"TCP traceroute failed: {hops[0]['error']}")
                else:
                    self.print_info(f"TCP traceroute to {ip}:")
                    for hop in hops:
                        if "hop" in hop and "ip" in hop:
                            print(f"  {hop['hop']} {hop['ip']} {' '.join(hop.get('times', []))}")
        
        elif cmd == "scan":
            if len(parts) < 2:
                self.print_error("Usage: scan <IP>")
            else:
                ip = parts[1]
                open_ports = self.scan_ip(ip)
                if "error" in open_ports:
                    self.print_error(f"Scan failed: {open_ports['error']}")
                else:
                    if not open_ports:
                        self.print_info(f"No open ports found on {ip}")
                    else:
                        self.print_info(f"Open ports on {ip}:")
                        for port, service in open_ports.items():
                            print(f"  Port {port} ({service})")
        
        elif cmd == "deep":
            if len(parts) < 3:
                self.print_error("Usage: deep scan <IP>")
            elif parts[1].lower() == "scan":
                ip = parts[2]
                open_ports = self.deep_scan_ip(ip)
                if "error" in open_ports:
                    self.print_error(f"Deep scan failed: {open_ports['error']}")
                else:
                    if not open_ports:
                        self.print_info(f"No open ports found on {ip}")
                    else:
                        self.print_info(f"Open ports on {ip} (deep scan):")
                        for port, service in open_ports.items():
                            print(f"  Port {port} ({service})")
            else:
                self.print_error("Usage: deep scan <IP>")
        
        else:
            self.print_error(f"Unknown command: {cmd}")
        
        return True
    
    def run(self):
        """Main run loop"""
        self.print_banner()
        self.print_help()
        
        # Initialize Telegram if configured
        if self.config.get("telegram_token") and self.config.get("telegram_chat_id"):
            if self.initialize_telegram():
                self.start_telegram_bot()
        
        # Main command loop
        try:
            while True:
                try:
                    command = input(f"{RED}cyber-tool>{RESET} ").strip()
                    if not self.process_command(command):
                        break
                except KeyboardInterrupt:
                    print()  # New line after Ctrl+C
                    self.print_info("Use 'exit' to quit the program")
                except EOFError:
                    break
        except Exception as e:
            self.print_error(f"Unexpected error: {str(e)}")
        finally:
            self.stop_monitoring()
            self.print_info("Goodbye!")

def main():
    """Main function"""
    tool = CyberSecurityTool()
    tool.run()

if __name__ == "__main__":
    main()