#!/usr/bin/env python3
"""
port-registry - Like nmcli for local port management
A unified control plane for tracking, allocating, and resolving port conflicts
"""

import json
import os
import sys
import subprocess
import argparse
import socket
import time
import signal
import readline
import atexit
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from collections import defaultdict

# ============================================================================
# Configuration
# ============================================================================
# CONFIG_DIR = Path.home() / ".config" / "port-registry"
CONFIG_DIR = Path('/home/zymacs') / ".config" / "port-registry"
STATE_FILE = CONFIG_DIR / "state.json" 
HISTORY_FILE = CONFIG_DIR / "history.json"
SOCKET_PATH = Path("/tmp") / f"port-registry-{os.getenv('USER')}.sock"

DEFAULT_PORT_RANGE = (3000, 10000)
WELL_KNOWN_PORTS = {
    22: "ssh", 80: "http", 443: "https", 5432: "postgres",
    3306: "mysql", 6379: "redis", 27017: "mongodb", 8080: "tomcat",
    9000: "minio", 5000: "flask", 8000: "django", 4200: "angular",
    3000: "react", 8081: "jenkins", 15672: "rabbitmq", 9200: "elasticsearch"
}

# ============================================================================
# Data Models
# ============================================================================

@dataclass
class PortEntry:
    port: int
    pid: Optional[int]
    user: str
    process: str
    command: str
    service_name: Optional[str]
    detected_at: str
    is_registered: bool = False

@dataclass
class ServiceRegistration:
    name: str
    port: int
    user: str
    registered_at: str
    context: str = "default"
    auto_start_cmd: Optional[str] = None

@dataclass
class Context:
    name: str
    port_range_start: int
    port_range_end: int
    description: str = ""

# ============================================================================
# Core Scanner (works without sudo, optional privileged mode)
# ============================================================================

class PortScanner:
    def __init__(self, use_privileged: bool = False):
        self.use_privileged = use_privileged
    
    def scan(self) -> Dict[int, PortEntry]:
        """Scan all listening ports and return PortEntry objects"""
        try:
            if self.use_privileged:
                return self._scan_privileged()
            else:
                return self._scan_unprivileged()
        except Exception as e:
            print(f"Scan failed: {e}", file=sys.stderr)
            return {}
    
    def _scan_unprivileged(self) -> Dict[int, PortEntry]:
        """Scan using lsof (shows only user's processes)"""
        print("[!] Unpriviledged scan shows only user's processes. Might mark port as free yet in use by other user process")
        try:
            result = subprocess.run(
                ["lsof", "-i", "-P", "-n", "-sTCP:LISTEN"],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode != 0:
                return self._fallback_netstat()
            return self._parse_lsof_output(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return self._fallback_netstat()
    
    def _scan_privileged(self) -> Dict[int, PortEntry]:
        """Attempt privileged scan via sudo or capabilities"""
        try:
            # Try with sudo first
            result = subprocess.run(
                ["sudo", "lsof", "-i", "-P", "-n", "-sTCP:LISTEN"],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0:
                return self._parse_lsof_output(result.stdout)
        except:
            pass
        
        # Fallback to ss with sudo (more portable)
        try:
            result = subprocess.run(
                ["sudo", "ss", "-tlnp"],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0:
                return self._parse_ss_output(result.stdout)
        except:
            pass
        
        return self._scan_unprivileged()
    
    def _parse_lsof_output(self, output: str) -> Dict[int, PortEntry]:
        ports = {}
        lines = output.strip().split('\n')
        if len(lines) < 2:
            return ports
        
        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) < 9:
                continue
            
            process = parts[0]
            pid = int(parts[1]) if parts[1].isdigit() else None
            user = parts[2] if len(parts) > 2 else "unknown"
            addr_port = parts[8] if len(parts) > 8 else ""
            
            if ":" in addr_port:
                port_str = addr_port.split(":")[-1]
                if port_str.isdigit():
                    port = int(port_str)
                    command = " ".join(parts[9:]) if len(parts) > 9 else process
                    
                    ports[port] = PortEntry(
                        port=port, pid=pid, user=user, process=process,
                        command=command, service_name=None,
                        detected_at=datetime.now().isoformat(),
                        is_registered=False
                    )
        return ports
    
    def _parse_ss_output(self, output: str) -> Dict[int, PortEntry]:
        ports = {}
        for line in output.strip().split('\n')[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            
            # Format: LISTEN 0 128 0.0.0.0:5432 0.0.0.0:* users:(("postgres",pid=1234,fd=3))
            addr_port = parts[3] if len(parts) > 3 else ""
            if ":" in addr_port:
                port_str = addr_port.split(":")[-1]
                if port_str.isdigit():
                    port = int(port_str)
                    
                    # Extract process info
                    process_info = parts[5] if len(parts) > 5 else ""
                    pid = None
                    process = "unknown"
                    if 'users:((' in process_info:
                        # Parse users:(("postgres",pid=1234,fd=3))
                        import re
                        match = re.search(r'"([^"]+)",pid=(\d+)', process_info)
                        if match:
                            process = match.group(1)
                            pid = int(match.group(2))
                    
                    ports[port] = PortEntry(
                        port=port, pid=pid, user="unknown", process=process,
                        command=process, service_name=None,
                        detected_at=datetime.now().isoformat(),
                        is_registered=False
                    )
        return ports
    
    def _fallback_netstat(self) -> Dict[int, PortEntry]:
        """Last resort: use netstat"""
        try:
            result = subprocess.run(
                ["netstat", "-tuln"],
                capture_output=True, text=True, timeout=3
            )
            ports = {}
            for line in result.stdout.split('\n'):
                if 'LISTEN' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        addr_port = parts[3]
                        if ":" in addr_port:
                            port_str = addr_port.split(":")[-1]
                            if port_str.isdigit():
                                port = int(port_str)
                                ports[port] = PortEntry(
                                    port=port, pid=None, user="unknown",
                                    process="unknown", command="unknown",
                                    service_name=None,
                                    detected_at=datetime.now().isoformat(),
                                    is_registered=False
                                )
            return ports
        except:
            return {}

# ============================================================================
# Persistent State Management
# ============================================================================

class StateManager:
    def __init__(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self.state = self._load_state()
        self.history = self._load_history()
    
    def _load_state(self) -> dict:
        if STATE_FILE.exists():
            try:
                return json.loads(STATE_FILE.read_text())
            except:
                return self._default_state()
        return self._default_state()
    
    def _default_state(self) -> dict:
        return {
            "services": {},  # service_name -> ServiceRegistration dict
            "contexts": {
                "default": {
                    "name": "default",
                    "port_range_start": 3000,
                    "port_range_end": 10000,
                    "description": "Default development context"
                }
            },
            "active_context": "default",
            "port_claims": {}  # port -> service_name (for auto-assigned ports)
        }
    
    def _load_history(self) -> list:
        if HISTORY_FILE.exists():
            try:
                return json.loads(HISTORY_FILE.read_text())
            except:
                pass
                # return []
        return []
    
    def save(self):
        STATE_FILE.write_text(json.dumps(self.state, indent=2))
        HISTORY_FILE.write_text(json.dumps(self.history[-1000:], indent=2))  # Keep last 1000
    
    def add_history(self, action: str, details: dict):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details
        }
        self.history.append(entry)
        self.save()
    
    def register_service(self, name: str, port: int, user: str, context: str = None, auto_start: str = None):
        if context is None:
            context = self.state["active_context"]
        
        registration = ServiceRegistration(
            name=name, port=port, user=user,
            registered_at=datetime.now().isoformat(),
            context=context, auto_start_cmd=auto_start
        )
        self.state["services"][name] = asdict(registration)
        self.state["port_claims"][str(port)] = name
        self.add_history("register", {"name": name, "port": port, "context": context})
        self.save()
        return registration
    
    def unregister_service(self, name: str):
        if name in self.state["services"]:
            port = self.state["services"][name]["port"]
            del self.state["services"][name]
            if str(port) in self.state["port_claims"]:
                del self.state["port_claims"][str(port)]
            self.add_history("unregister", {"name": name})
            self.save()
            return True
        return False
    
    def get_service(self, name: str) -> Optional[ServiceRegistration]:
        if name in self.state["services"]:
            return ServiceRegistration(**self.state["services"][name])
        return None
    
    def get_context(self, name: str) -> Optional[Context]:
        if name in self.state["contexts"]:
            return Context(**self.state["contexts"][name])
        return None
    
    def create_context(self, name: str, start: int, end: int, description: str = ""):
        self.state["contexts"][name] = {
            "name": name, "port_range_start": start,
            "port_range_end": end, "description": description
        }
        self.save()
    
    def get_next_free_port(self, scanner: PortScanner, prefer: int = None, context: str = None) -> int:
        """Find the next free port in the current context range"""
        if context is None:
            context = self.state["active_context"]
        
        ctx = self.get_context(context)
        if not ctx:
            ctx = Context(name="default", port_range_start=3000, port_range_end=10000)
        
        used = set(scanner.scan().keys())
        used.update([int(p) for p in self.state["port_claims"].keys()])
        
        if prefer and prefer not in used and ctx.port_range_start <= prefer <= ctx.port_range_end:
            return prefer
        
        for port in range(ctx.port_range_start, ctx.port_range_end + 1):
            if port not in used:
                return port
        
        raise RuntimeError(f"No free ports in range {ctx.port_range_start}-{ctx.port_range_end}")

# ============================================================================
# Main Application
# ============================================================================

class PortRegistry:
    def __init__(self, use_privileged=False):
        self.state = StateManager()
        self.scanner = PortScanner(use_privileged) # do so if user  used sudo
        self.privileged_scanner = PortScanner(use_privileged) # do if user used sudo
    
    def _format_table(self, data: List[dict], headers: List[str]) -> str:
        """Format data as aligned table"""
        if not data:
            return "No data"
        
        # Calculate column widths
        col_widths = {h: len(h) for h in headers}
        for row in data:
            for h in headers:
                val = str(row.get(h, ""))
                col_widths[h] = max(col_widths[h], len(val))
        
        # Build table
        lines = []
        header_line = "  ".join(h.ljust(col_widths[h]) for h in headers)
        lines.append(header_line)
        lines.append("-" * len(header_line))
        
        for row in data:
            line = "  ".join(str(row.get(h, "")).ljust(col_widths[h]) for h in headers)
            lines.append(line)
        
        return "\n".join(lines)
    
    def cmd_port_list(self, args):
        """List all ports and what's using them"""
        ports = self.scanner.scan()
        
        if args.all:
            ports = self.privileged_scanner.scan()
        
        if not ports:
            print("No listening ports found")
            return
        
        data = []
        for port, entry in sorted(ports.items()):
            # Check if registered
            service_name = self.state.state["port_claims"].get(str(port))
            if not service_name and port in WELL_KNOWN_PORTS:
                service_name = WELL_KNOWN_PORTS[port]
            
            data.append({
                "PORT": port,
                "SERVICE": service_name or "-",
                "USER": entry.user,
                "PID": entry.pid or "-",
                "PROCESS": entry.process[:30]
            })
        
        print(self._format_table(data, ["PORT", "SERVICE", "USER", "PID", "PROCESS"]))
        
        if not args.all and not self.scanner.use_privileged:
            print("\n💡 Showing only your processes. Use --all to see all ports (may require sudo)")
    
    def cmd_port_show(self, args):
        """Show detailed information about a specific port"""
        ports = self.scanner.scan()
        if args.all:
            ports = self.privileged_scanner.scan()
        
        if args.port not in ports:
            print(f"Port {args.port} is not in use")
            # Check if registered but not running
            service = self.state.state["port_claims"].get(str(args.port))
            if service:
                print(f"  Registered to: {service} (but not currently listening)")
            return
        
        entry = ports[args.port]
        print(f"Port {args.port}:")
        print(f"  Process: {entry.process}")
        print(f"  PID: {entry.pid or 'unknown'}")
        print(f"  User: {entry.user}")
        print(f"  Command: {entry.command}")
        
        # Check registration
        service = self.state.state["port_claims"].get(str(args.port))
        if service:
            print(f"  Registered service: {service}")
        else:
            print(f"  ℹ️ Not registered. Run: port-registry service register --name <name> --port {args.port}")
    
    def cmd_port_allocate(self, args):
        """Allocate a new port for a service"""
        context = args.context or self.state.state["active_context"]
        
        try:
            port = self.state.get_next_free_port(
                self.scanner, 
                prefer=args.prefer,
                context=context
            )
            
            service_name = args.service or f"service-{port}"
            
            # Register the service
            self.state.register_service(
                name=service_name,
                port=port,
                user=os.getenv("USER", "unknown"),
                context=context,
                auto_start=args.auto_start
            )
            
            print(f"✅ Allocated port {port} for service '{service_name}'")
            print(f"   Context: {context}")
            if args.auto_start:
                print(f"   Auto-start: {args.auto_start}")
            
            # Save to history
            self.state.add_history("allocate", {"port": port, "service": service_name})
            
        except RuntimeError as e:
            print(f"❌ Allocation failed: {e}")
            return 1
        
        return 0
    
    def cmd_service_list(self, args):
        """List registered services"""
        services = self.state.state["services"]
        
        if not services:
            print("No services registered")
            print("  Run: port-registry service register --name <name> --port <port>")
            return
        
        # Check which services are actually running
        running_ports = self.scanner.scan()
        
        data = []
        
        for name, reg in services.items():
            is_running = reg["port"] in running_ports
            auto_start = reg.get("auto_start_cmd", "-")
            data.append({
                "NAME": name,
                "PORT": reg["port"],
                "CONTEXT": reg["context"],
                "STATUS": "🟢 running" if is_running else "⚫ stopped",
                "AUTO_START": auto_start[:20] if auto_start else []
            })
        
        print(self._format_table(data, ["NAME", "PORT", "CONTEXT", "STATUS", "AUTO_START"]))
    
    def cmd_service_register(self, args):
        """Register a service manually"""
        # Check if port is already registered
        existing = self.state.state["port_claims"].get(str(args.port))
        if existing and not args.force:
            print(f"❌ Port {args.port} already registered to '{existing}'")
            print("   Use --force to override")
            return 1
        
        # Check if port is in use
        ports = self.scanner.scan()
        if args.port in ports and not args.force:
            print(f"⚠️ Port {args.port} is currently in use by {ports[args.port].process}")
            print("   Use --force to register anyway")
            return 1
        
        self.state.register_service(
            name=args.name,
            port=args.port,
            user=os.getenv("USER", "unknown"),
            context=args.context,
            auto_start=args.auto_start
        )
        
        print(f"✅ Registered service '{args.name}' on port {args.port}")
        if args.auto_start:
            print(f"   Auto-start command: {args.auto_start}")
        
        return 0
    
    def cmd_service_unregister(self, args):
        """Unregister a service"""
        if self.state.unregister_service(args.name):
            print(f"[*] Unregistered service '{args.name}'")
        else:
            print(f"[x] Service '{args.name}' not found")
            return 1
        return 0
    
    def cmd_service_start(self, args):
        """Start a registered service (if auto_start_cmd defined)"""
        service = self.state.get_service(args.name)
        if not service:
            print(f"❌ Service '{args.name}' not found")
            return 1
        
        if not service.auto_start_cmd:
            print(f"⚠️ No auto-start command defined for '{args.name}'")
            print(f"   Registered with: port-registry service register --auto-start 'cmd'")
            return 1
        
        print(f"🚀 Starting {args.name}...")
        try:
            # Run in background
            subprocess.Popen(
                service.auto_start_cmd,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            print(f"✅ Started {args.name} (may take a moment to bind to port {service.port})")
            
            # Wait a bit and check if it's running
            time.sleep(2)
            ports = self.scanner.scan()
            if service.port in ports:
                print(f"✅ Service is now listening on port {service.port}")
            else:
                print(f"⚠️ Service started but not yet listening on port {service.port}")
        except Exception as e:
            print(f"❌ Failed to start: {e}")
            return 1
        
        return 0
    
    def cmd_context_list(self, args):
        """List available contexts"""
        contexts = self.state.state["contexts"]
        active = self.state.state["active_context"]
        
        data = []
        for name, ctx in contexts.items():
            data.append({
                "NAME": name,
                "ACTIVE": "✓" if name == active else "",
                "PORT_RANGE": f"{ctx['port_range_start']}-{ctx['port_range_end']}",
                "DESCRIPTION": ctx.get("description", "")[:40]
            })
        
        print(self._format_table(data, ["NAME", "ACTIVE", "PORT_RANGE", "DESCRIPTION"]))
    
    def cmd_context_create(self, args):
        """Create a new context"""
        if args.name in self.state.state["contexts"]:
            print(f"❌ Context '{args.name}' already exists")
            return 1
        
        self.state.create_context(
            name=args.name,
            start=args.start,
            end=args.end,
            description=args.description
        )
        
        print(f"[*] Created context '{args.name}' with port range {args.start}-{args.end}")
        return 0
    
    def cmd_context_use(self, args):
        """Switch to a different context"""
        if args.name not in self.state.state["contexts"]:
            print(f"❌ Context '{args.name}' not found")
            print(f"   Available: {', '.join(self.state.state['contexts'].keys())}")
            return 1
        
        self.state.state["active_context"] = args.name
        self.state.save()
        print(f"✅ Switched to context '{args.name}'")
        return 0
    
    def cmd_conflict_list(self, args):
        """List port conflicts"""
        ports = self.scanner.scan()
        claimed = self.state.state["port_claims"]
        
        conflicts = []
        for port_str, service in claimed.items():
            port = int(port_str)
            if port in ports:
                conflicts.append({
                    "PORT": port,
                    "SERVICE": service,
                    "CONFLICT_WITH": ports[port].process
                })
        
        if not conflicts:
            print("No conflicts detected")
            return
        
        print(self._format_table(conflicts, ["PORT", "SERVICE", "CONFLICT_WITH"]))
        print("\n💡 Resolve with: port-registry conflict resolve <port>")
    
    def cmd_conflict_resolve(self, args):
        """Resolve a port conflict"""
        port = args.port
        
        ports = self.scanner.scan()
        if port not in ports:
            print(f"No conflict - port {port} is free")
            return 0
        
        if args.free:
            # Suggest killing the process
            entry = ports[port]
            print(f"Port {port} is in use by {entry.process} (PID {entry.pid})")
            if args.yes or input(f"Kill process {entry.pid}? [y/N]: ").lower() == 'y':
                try:
                    subprocess.run(["kill", "-9", str(entry.pid)], check=True)
                    print(f"✅ Killed process {entry.pid}")
                    time.sleep(1)
                    return 0
                except Exception as e:
                    print(f"❌ Failed to kill: {e}")
                    return 1
            else:
                print("Cancelled")
                return 0
        
        elif args.move_to:
            # Move service to new port
            service = self.state.state["port_claims"].get(str(port))
            if service:
                new_port = args.move_to
                print(f"Moving '{service}' from {port} to {new_port}")
                self.state.unregister_service(service)
                self.state.register_service(service, new_port, os.getenv("USER", "unknown"))
                print(f"✅ Updated registration. Update your service to use port {new_port}")
            else:
                print(f"No registered service on port {port}")
                return 1
        
        else:
            # Just show info
            entry = ports[port]
            print(f"Port {port} conflict:")
            print(f"  Current user: {entry.process} (PID {entry.pid}, user {entry.user})")
            service = self.state.state["port_claims"].get(str(port))
            if service:
                print(f"  Registered to: {service}")
            print("\nOptions:")
            print(f"  • port-registry conflict resolve {port} --free (kill the process)")
            print(f"  • port-registry conflict resolve {port} --move-to <newport>")
            print(f"  • port-registry port allocate --prefer {port} (will find next free)")
        
        return 0
    
    def cmd_monitor(self, args):
        """Monitor port changes in real-time"""
        print(f"Monitoring ports (press Ctrl+C to stop)...")
        print("=" * 60)
        
        last_state = {}
        
        def signal_handler(sig, frame):
            print("\n👋 Monitoring stopped")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
        try:
            while True:
                current = self.scanner.scan()
                
                # New ports
                for port in current:
                    if port not in last_state:
                        entry = current[port]
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] 🟢 Port {port} taken by {entry.process} (PID {entry.pid})")
                
                # Released ports
                for port in last_state:
                    if port not in current:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔴 Port {port} released")
                
                last_state = current
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n👋 Monitoring stopped")
    
    def cmd_connect(self, args):
        """Connect to a service (set environment variables)"""
        service = self.state.get_service(args.name)
        if not service:
            print(f"❌ Service '{args.name}' not registered")
            print(f"   Register with: port-registry service register --name {args.name} --port <port>")
            return 1
        
        # Start if not running
        ports = self.scanner.scan()
        if service.port not in ports and service.auto_start_cmd:
            print(f"⚠️ {args.name} is not running. Starting...")
            self.cmd_service_start(args)
            time.sleep(2)
            ports = self.scanner.scan()
        
        if service.port not in ports:
            print(f"❌ {args.name} is not running on port {service.port}")
            if service.auto_start_cmd:
                print(f"   Try: port-registry service start {args.name}")
            return 1
        
        # Generate environment variables
        env_vars = {
            f"{args.name.upper()}_PORT": str(service.port),
            f"{args.name.upper()}_HOST": "localhost",
            "PORT": str(service.port) if args.export_as_port else None
        }
        
        if args.shell:
            # Output shell commands to source
            for key, val in env_vars.items():
                if val:
                    print(f"export {key}={val}")
            
            # Also output connection info
            print(f"echo 'Connected to {args.name} on port {service.port}' >&2")
        else:
            print(f"✅ Connected to {args.name} on port {service.port}")
            print(f"   Set environment variables:")
            for key, val in env_vars.items():
                if val:
                    print(f"     {key}={val}")
        
        return 0

# ============================================================================
# CLI Entry Point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="port-registry - Like nmcli but for local port management",
        epilog="Examples:\n"
               "  port-registry port list\n"
               "  port-registry port allocate --service myapp\n"
               "  port-registry service register --name postgres --port 5432\n"
               "  port-registry connect postgres"
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # port list
    parser_port_list = subparsers.add_parser("port-list", aliases=["pl"], help="List ports")
    parser_port_list.add_argument("--all", "-a", action="store_true", help="Show all ports (requires sudo)")
    parser_port_list.set_defaults(func=lambda reg, args: reg.cmd_port_list(args))
    
    # port show
    parser_port_show = subparsers.add_parser("port-show", aliases=["ps"], help="Show port details")
    parser_port_show.add_argument("port", type=int, help="Port number")
    parser_port_show.add_argument("--all", "-a", action="store_true", help="Include system ports")
    parser_port_show.set_defaults(func=lambda reg, args: reg.cmd_port_show(args))
    
    # port allocate
    parser_alloc = subparsers.add_parser("port-allocate", aliases=["pa"], help="Allocate a new port")
    parser_alloc.add_argument("--service", "-s", help="Service name")
    parser_alloc.add_argument("--prefer", "-p", type=int, help="Preferred port")
    parser_alloc.add_argument("--context", "-c", help="Context to use")
    parser_alloc.add_argument("--auto-start", "-as", help="Command to auto-start the service")
    parser_alloc.set_defaults(func=lambda reg, args: reg.cmd_port_allocate(args))
    
    # service list
    parser_svc_list = subparsers.add_parser("service-list", aliases=["sl"], help="List services")
    parser_svc_list.set_defaults(func=lambda reg, args: reg.cmd_service_list(args))
    
    # service register
    parser_svc_reg = subparsers.add_parser("service-register", aliases=["sr"], help="Register a service")
    parser_svc_reg.add_argument("--name", "-n", required=True, help="Service name")
    parser_svc_reg.add_argument("--port", "-p", type=int, required=True, help="Port number")
    parser_svc_reg.add_argument("--context", "-c", help="Context")
    parser_svc_reg.add_argument("--auto-start", help="Command to start the service")
    parser_svc_reg.add_argument("--force", "-f", action="store_true", help="Force registration")
    parser_svc_reg.set_defaults(func=lambda reg, args: reg.cmd_service_register(args))
    
    # service unregister
    parser_svc_unreg = subparsers.add_parser("service-unregister", aliases=["su"], help="Unregister a service")
    parser_svc_unreg.add_argument("name", help="Service name")
    parser_svc_unreg.set_defaults(func=lambda reg, args: reg.cmd_service_unregister(args))
    
    # service start
    parser_svc_start = subparsers.add_parser("service-start", aliases=["ss"], help="Start a service")
    parser_svc_start.add_argument("name", help="Service name")
    parser_svc_start.set_defaults(func=lambda reg, args: reg.cmd_service_start(args))
    
    # context list
    parser_ctx_list = subparsers.add_parser("context-list", aliases=["cl"], help="List contexts")
    parser_ctx_list.set_defaults(func=lambda reg, args: reg.cmd_context_list(args))
    
    # context create
    parser_ctx_create = subparsers.add_parser("context-create", aliases=["cc"], help="Create context")
    parser_ctx_create.add_argument("name", help="Context name")
    parser_ctx_create.add_argument("--start", type=int, default=3000, help="Start port")
    parser_ctx_create.add_argument("--end", type=int, default=10000, help="End port")
    parser_ctx_create.add_argument("--description", "-d", help="Description")
    parser_ctx_create.set_defaults(func=lambda reg, args: reg.cmd_context_create(args))
    
    # context use
    parser_ctx_use = subparsers.add_parser("context-use", aliases=["cu"], help="Switch context")
    parser_ctx_use.add_argument("name", help="Context name")
    parser_ctx_use.set_defaults(func=lambda reg, args: reg.cmd_context_use(args))
    
    # conflict list
    parser_conf_list = subparsers.add_parser("conflict-list", aliases=["conf-list"], help="List conflicts")
    parser_conf_list.set_defaults(func=lambda reg, args: reg.cmd_conflict_list(args))
    
    # conflict resolve
    parser_conf_resolve = subparsers.add_parser("conflict-resolve", aliases=["cr"], help="Resolve conflict")
    parser_conf_resolve.add_argument("port", type=int, help="Port in conflict")
    parser_conf_resolve.add_argument("--free", action="store_true", help="Kill the process")
    parser_conf_resolve.add_argument("--move-to", type=int, help="Move service to new port")
    parser_conf_resolve.add_argument("--yes", "-y", action="store_true", help="Auto-confirm")
    parser_conf_resolve.set_defaults(func=lambda reg, args: reg.cmd_conflict_resolve(args))
    
    # monitor
    parser_mon = subparsers.add_parser("monitor", aliases=["m"], help="Monitor port changes")
    parser_mon.add_argument("--interval", "-i", type=int, default=2, help="Scan interval (seconds)")
    parser_mon.set_defaults(func=lambda reg, args: reg.cmd_monitor(args))
    
    # connect
    parser_connect = subparsers.add_parser("connect", aliases=["c"], help="Connect to a service")
    parser_connect.add_argument("name", help="Service name")
    parser_connect.add_argument("--shell", action="store_true", help="Output shell commands")
    parser_connect.add_argument("--export-as-port", action="store_true", help="Also set PORT env var")
    parser_connect.set_defaults(func=lambda reg, args: reg.cmd_connect(args))
    
    # Parse and run
    args = parser.parse_args()
    
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    running_user_id = os.getuid() 
    registry = PortRegistry(use_privileged=True if running_user_id == 0 else False)
    return args.func(registry, args)

if __name__ == "__main__":
    sys.exit(main())
