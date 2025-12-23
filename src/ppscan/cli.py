import argparse
import asyncio
import sys
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from . import builder, scanner

console = Console()

def main():
    parser = argparse.ArgumentParser(description="ppscan - Prototype Pollution Fuzzer (Python port of ppfuzz)")
    parser.add_argument("-l", "--list", help="List of target URLs", required=False)
    parser.add_argument("-u", "--url", help="Target URL", required=False)
    parser.add_argument("-c", "--concurrency", help="Set the concurrency level", type=int, default=15)
    parser.add_argument("-t", "--timeout", help="Max. time allowed for connection (s)", type=int, default=30)
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)", type=str)
    parser.add_argument("--headers", help="Custom headers (JSON string or 'Key: Value')", type=str)
    parser.add_argument("--user-agent", help="Custom User-Agent", type=str)
    parser.add_argument("--exploit", help="Actively verify XSS by visiting potential URLs", action="store_true")
    parser.add_argument("--callback", help="Callback URL for SSRF detection (default: attacker.tld)", type=str, default="attacker.tld")
    parser.add_argument("--json", help="Output file for JSON results", type=str)
    
    parser.add_argument("--sspp", help="Enable Server-Side Prototype Pollution detection", action="store_true")
    
    args = parser.parse_args()
    
    header_text = Text(r"""
                 
   _ __  _ __  ___  ___ __ _ _ __ 
  | '_ \| '_ \/ __|/ __/ _` | '_ \
  | |_) | |_) \__ \ (_| (_| | | | |
  | .__/| .__/|___/\___\__,_|_| |_|
  |_|   |_|                        
   Prototype Pollution Scanner
   Original by dwisiswant0, Improved by ThemeHackers
    """, style="bold magenta")
    console.print(Panel(header_text, border_style="green"))
    
    urls = []
    
    if args.url:
        urls.append(args.url)

    if args.list:
        try:
            with open(args.list, "r") as f:
                urls.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"Error: File '{args.list}' not found.")
            sys.exit(1)
    
    if not urls and not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin if line.strip()]
    
    if not urls:
        parser.print_help()
        sys.exit(0)

    if not urls:
        console.print("[bold red]No URLs provided.[/bold red]")
        sys.exit(0)

    urls = [u for u in urls if u.startswith("http")]

    fuzzed_urls = []
    if args.sspp:
        fuzzed_urls = urls
        console.print(f"[bold cyan]Scanning {len(fuzzed_urls)} targets for Server-Side Prototype Pollution...[/bold cyan]")
    else:
        with console.status("[bold green]Generating payloads..."):
            for url in urls:
                fuzzed_urls.extend(builder.build_queries(url))
        console.print(f"[bold cyan]Scanning {len(fuzzed_urls)} fuzzed URLs generated from {len(urls)} targets...[/bold cyan]")

    import json

    custom_headers = {}
    if args.headers:
        try:
            custom_headers = json.loads(args.headers)
        except json.JSONDecodeError:
            if ":" in args.headers:
                parts = args.headers.split(":", 1)
                custom_headers = {parts[0].strip(): parts[1].strip()}
            else:
                console.print("[bold yellow]Warning: could not parse headers. Use JSON or 'Key: Value'.[/bold yellow]")

    scan_engine = scanner.Scanner(
        concurrency=args.concurrency, 
        timeout=args.timeout,
        proxy=args.proxy,
        headers=custom_headers,
        user_agent=args.user_agent,
        verify_exploit=args.exploit,
        callback_url=args.callback,
        sspp=args.sspp
    )
    try:
        results = asyncio.run(scan_engine.scan(fuzzed_urls))
        
        if args.json:
            with open(args.json, "w") as f:
                json.dump(results, f, indent=4)
            console.print(f"[bold green]Results saved to {args.json}[/bold green]")
            
    except KeyboardInterrupt:
        console.print("\n[bold red]Interrupted.[/bold red]")
        sys.exit(0)

if __name__ == "__main__":
    main()
