# Logic1: HTTP 보안 헤더 분석기 (최종 안정판)
import requests
import os, sys, json, time, re
from http.cookies import SimpleCookie

class Logic1:
    def __init__(self, base_url: str):
        self.base_url = (base_url or "").strip()
        self.content = None
        self.headers = {}
        self.result = {}

        # path (결과는 파일로 저장)
        self.total_path = "/root/project"
        os.makedirs(self.total_path, exist_ok=True)
        print(f"[INFO] {self.total_path} 디렉토리 확인 완료")

        self.Logic1_result_path = os.path.join(self.total_path, "logic1_result.json")

    def delete_file(self):
        """이전 결과 파일 삭제"""
        try:
            if os.path.isfile(self.Logic1_result_path):
                os.remove(self.Logic1_result_path)
                print(f"[INFO] 기존 {self.Logic1_result_path} 파일 삭제 완료")
            elif not os.path.isfile(self.Logic1_result_path):
                print(f"[INFO] 기존 {self.Logic1_result_path} 파일이 존재하지 않습니다.")
        except Exception as e:
            print(f"[ERROR] 파일 삭제 실패: {e}")

    def analyze_url(self, timeout: int = 10):
        """HEAD 요청 → 실패 시 GET 요청. 헤더를 소문자 키로 정규화"""
        try:
            resp = requests.head(self.base_url, allow_redirects=True, timeout=timeout)
            if resp.status_code >= 400 or not resp.headers:
                resp = requests.get(self.base_url, allow_redirects=True, timeout=timeout)
            self.content = resp
            # 모든 헤더 키를 소문자로 변환 (대소문자 문제 해결)
            self.headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as e:
            print(f"[ERROR] 요청 실패: {e}")
            self.content = None
            self.headers = {}

    def _check_hsts(self, val: str):
        """HSTS 헤더 검증"""
        if not val:
            return {"present": False, "max_age": None, "ok": False}
        parts = [p.strip() for p in val.split(";")]
        max_age = None
        for p in parts:
            if p.lower().startswith("max-age"):
                try:
                    max_age = int(p.split("=")[1])
                except Exception:
                    max_age = None
        return {"present": True, "max_age": max_age, "ok": (isinstance(max_age, int) and max_age >= 31536000)}

    def _check_csp(self, val: str):
        """CSP 검사 — report-only도 감지."""
        if not val:
            return {"present": False, "report_only": False, "has_unsafe_inline": False, "allows_all": False}
        low = val.lower()
        # report-only 여부 판단 (헤더이름으로 따로 처리해도 무방)
        report_only = "report-only" in low or "report-only" in (self.headers.get("content-security-policy-report-only","").lower())
        return {
            "present": True,
            "report_only": report_only,
            "has_unsafe_inline": ("'unsafe-inline'" in low),
            "allows_all": ("default-src *" in low or " * " in low)
        }

    def _check_set_cookie(self, header_value: str):
        cookies = []
        if not header_value:
            return cookies
        parts = [p.strip() for p in re.split(r',\s*(?=[^;]+=)', header_value) if p.strip()]  # 대충의 멀티쿠키 분리
        for p in parts:
            try:
                # SameSite 끝 쉼표 제거
                p = re.sub(r'(samesite\s*=\s*)([^;,\s]+),', r'\1\2', p, flags=re.I)
                c = SimpleCookie()
                c.load(p)
                for name, morsel in c.items():
                    samesite = morsel.get('samesite') or None
                    if isinstance(samesite, str):
                        samesite = samesite.rstrip(',').lower()
                    attrs = {
                        "name": name,
                        "value": morsel.value,
                        "secure": ('secure' in p.lower()) or (morsel.get('secure') != ""),
                        "httponly": ('httponly' in p.lower()) or (morsel.get('httponly') != ""),
                        "samesite": samesite
                    }
                    cookies.append(attrs)
            except Exception:
                attrs = {
                    "raw": p,
                    "secure": "secure" in p.lower(),
                    "httponly": "httponly" in p.lower(),
                    "samesite": re.search(r'samesite\s*=\s*([^;,\s]+)', p, re.I).group(1).rstrip(',') if re.search(r'samesite\s*=\s*([^;,\s]+)', p, re.I) else None
                }
                cookies.append(attrs)
        return cookies

    def analyze_security_headers(self):
        """보안 헤더 분석 (대소문자 무시 방식으로 조회)"""
        checks = {}
        hdr = lambda name: self.headers.get(name.lower(), "")

        # 기본 존재 여부 확인
        checks['server'] = {"present": bool(hdr("server")), "value": hdr("server")}
        checks['hsts'] = self._check_hsts(hdr("strict-transport-security"))
        checks['csp'] = self._check_csp(hdr("content-security-policy"))
        xfo = hdr("x-frame-options")
        checks['x_frame_options'] = {"present": bool(xfo), "value": xfo, "ok": xfo.strip().upper() in ("DENY", "SAMEORIGIN")}
        xcto = hdr("x-content-type-options")
        checks['x_content_type_options'] = {"present": bool(xcto), "value": xcto, "ok": xcto.strip().lower() == "nosniff"}
        checks['referrer_policy'] = {"present": bool(hdr("referrer-policy")), "value": hdr("referrer-policy")}
        pp = hdr("permissions-policy") or hdr("feature-policy")
        checks['permissions_policy'] = {"present": bool(pp), "value": pp}
        sc = hdr("set-cookie")
        checks['cookies'] = self._check_set_cookie(sc)

        # 보안 취약점 요약
        severity = []
        if not self.content:
            severity.append("ERROR: 헤더를 가져오지 못함")
        else:
            final_is_https = str(self.content.url).lower().startswith("https://")
            if not final_is_https:
                severity.append("[SIGNAL] 최종 URL이 HTTPS가 아님")

            if not checks['hsts']['present'] or not checks['hsts']['ok']:
                severity.append("[SIGNAL] HSTS 헤더 미설정 또는 max-age 기준 미충족")

            if not checks['csp']['present']:
                severity.append("[SIGNAL] CSP 헤더 미설정")
            else:
                if checks['csp']['has_unsafe_inline']:
                    severity.append("[SIGNAL] CSP에 'unsafe-inline' 포함")
                if checks['csp']['allows_all']:
                    severity.append("[SIGNAL] CSP 기본 소스 정책이 광범위함")

            if not checks['x_frame_options']['ok']:
                severity.append("[SIGNAL] X-Frame-Options 헤더 미설정 또는 비권장 값")

            if not checks['x_content_type_options']['ok']:
                severity.append("[SIGNAL] X-Content-Type-Options 헤더 미설정 또는 nosniff 아님")
            if checks['cookies']:
                for c in checks['cookies']:
                    if not c.get('secure'):
                        severity.append(f"[SIGNAL] 쿠키 '{c.get('name', c.get('raw',''))}' Secure 플래그 미설정")
                    if not c.get('httponly'):
                        severity.append(f"[SIGNAL] 쿠키 '{c.get('name', c.get('raw',''))}' HttpOnly 플래그 미설정")

            if checks['server']['present']:
                severity.append("[SIGNAL] Server 헤더 존재")

        self.result = {
            "url": self.base_url,
            "checked_at": int(time.time()),
            "final_url": getattr(self.content, "url", None),
            "headers": self.headers,
            "checks": checks,
            "summary": severity
        }
        return self.result

    def save_results(self):
        """결과를 JSON으로 저장"""
        try:
            with open(self.Logic1_result_path, "w", encoding="utf-8") as f:
                json.dump(self.result, f, ensure_ascii=False, indent=2)
            print(f"[OK] 결과 저장 완료 → {self.Logic1_result_path}")
        except Exception as e:
            print(f"[ERROR] 결과 저장 실패: {e}")

    def openfile(self):
        """결과 파일 열기"""
        try:
            if os.path.isfile(self.Logic1_result_path):
                with open(self.Logic1_result_path, "r", encoding="utf-8") as f:
                    data = f.read()
                    print("[INFO] 파일 읽기 성공\n")
                    print(data)
        except Exception as e:
            print(f"[ERROR] 파일 읽기 실패: {e}")


if __name__ == "__main__":
    url = input("분석할 URL 입력: ").strip()
    if not url:
        print("URL을 입력하세요.")
        sys.exit(1)

    L1 = Logic1(url)
    L1.delete_file()
    L1.analyze_url()
    L1.analyze_security_headers()
    L1.save_results()
    L1.openfile()