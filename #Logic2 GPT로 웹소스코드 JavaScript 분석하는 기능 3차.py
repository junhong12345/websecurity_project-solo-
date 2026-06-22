#Logic2 GPT로 웹소스코드 JavaScript 분석하는 기능 3차 수정 , 최종본 

import os, re, sys, time, json

import requests
from openai import OpenAI

# --- stdout/stderr 인코딩 (환경 따라 생략 가능) ---
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")


class GPTJavaScriptScanner():
    def __init__(self):
        self.content = None
        self.result = {}
        self.final_result: list[str] = []

        #path
        self.total_path = "/root/project"
        self.api_path = os.path.join(self.total_path, "api_key")
        self.downloaded_path = os.path.join(self.total_path, "downloaded")
        self.index_html_path = os.path.join(self.downloaded_path, "index.html")
        self.combined_txt_path = os.path.join(self.downloaded_path, "combined.txt")
        
        #result path
        self.gpt_result_path = os.path.join(self.total_path, "gpt_js_result.json") #json 형식 
        self.gpt_result_txt_path = os.path.join(self.total_path, "gpt_js_result.txt") #txt 형식
        self.max_len = 50000
        self.full_code = ''
        self.chunks: list[str] = []
        self.summary_path = os.path.join(self.total_path, "gpt_js_summary.json")

        api_key_path = os.path.join(self.api_path, "api_key.txt")
        if os.path.isfile(api_key_path):
            try:
                with open(api_key_path, "r", encoding="utf-8") as f:
                    self.api_key = f.read().strip()
                    print(f"[INFO] api_key 읽기 성공")
            except Exception as e:
                print(f"ERROR: {e}")
        else:
            print(f"{api_key_path}파일을 찾을 수 없습니다.\n")
            print("프로그램을 종료합니다.")
            sys.exit(1)

        self.client = OpenAI(api_key=self.api_key)
        self.model_name = "gpt-4o-mini"

        # ----------------------------
        # SYSTEM PROMPT (문자 그대로)
        # ----------------------------
        self.SYSTEM_PROMPT = (
    "당신은 JavaScript 보안 분석 전문가입니다.\n"
    "아래에 제공되는 전체 JavaScript 코드(combined.txt)를 기반으로 "
    "취약점, 악성 행위, 개인정보 탈취, 크립토재킹, 난독화 여부 등을 "
    "정적 분석(Static Analysis) 방식으로 모두 조사하십시오.\n\n"

    "분석해야 할 항목은 다음과 같습니다.\n\n"

    "1. 취약점(Vulnerabilities) 탐지\n"
    "   - XSS(DOM 기반, reflected, stored)\n"
    "   - CSRF 관련 취약 패턴\n"
    "   - 입력값 검증 부족 (Validation Bypass)\n"
    "   - 위험한 DOM 조작(innerHTML 등)\n"
    "   - eval(), new Function() 사용\n"
    "   - Open Redirect\n"
    "   - Prototype Pollution 가능성\n"
    "   - 취약한 암호화 사용(MD5, SHA1, custom XOR 등)\n\n"

    "2. 개인정보 탈취(PII Stealing) 탐지\n"
    "   - keydown, input 이벤트 기반 키로깅\n"
    "   - 쿠키/토큰/세션 탈취(localStorage, sessionStorage 접근 포함)\n"
    "   - fetch, XHR, WebSocket 등으로 외부 전송 시도\n\n"

    "3. 악성 동작(Malicious Behavior)\n"
    "   - 크립토재킹(WebAssembly, 무한 hashing loop, setInterval miner)\n"
    "   - 동적으로 스크립트를 불러오는 행위\n"
    "   - 난독화(Obfuscation), 인코딩, 문자열 분할, 배열 기반 복호화\n"
    "   - Suspicious Domain으로의 fetch/XHR\n\n"

    "4. 민감정보(Secrets) 노출\n"
    "   - API Key\n"
    "   - 토큰, 인증정보\n"
    "   - 내부 시스템 주소 또는 config leak\n\n"

    "중요 규칙: 다음 항목들은 정상적인 웹 애플리케이션에서도 자주 사용되므로,\n"
    "단독으로는 악성 행위로 판단해서는 안 됩니다.\n\n"

    "[정상 패턴인데 악성처럼 보일 수 있는 사례들]\n\n"

    "1) innerHTML, insertAdjacentHTML 등의 사용\n"
    "   - SPA, CSR/SSR 미적용 웹사이트의 일반적인 DOM 업데이트 방식입니다.\n"
    "   - '사용자 입력 → innerHTML' 조합일 때만 위험합니다.\n\n"

    "2) 동적 스크립트 로딩 (document.createElement('script'))\n"
    "   - 광고/트래킹/분석/A/B 테스트에서 흔히 사용됩니다.\n"
    "   - 외부 URL이 난독화되었거나, 데이터 전송과 결합해야만 위험합니다.\n\n"

    "3) 난독화된 JavaScript 코드\n"
    "   - Webpack/Closure Compiler/UglifyJS 등 프로덕션 빌드의 일반적인 결과입니다.\n"
    "   - 난독화 단독 사용은 악성 근거가 아닙니다.\n\n"

    "4) localStorage / sessionStorage 접근\n"
    "   - 로그인 상태 유지, 사용자 설정 저장 등 정상적 용도입니다.\n"
    "   - 외부 전송(fetch/XHR/WebSocket)이 있어야만 위험합니다.\n\n"

    "5) keydown/input 이벤트 리스너\n"
    "   - 검색창, 단축키, 입력 폼, 접근성 기능에서 일반적으로 사용됩니다.\n"
    "   - 입력 정보가 외부로 전송될 때에만 keylogger 의심입니다.\n\n"

    "평가 원칙:\n"
    "- '패턴 존재'만으로 악성 판단을 하지 마십시오.\n"
    "- 반드시 '악성 목적(flow)' 또는 '데이터 전송/조작'이 있는지 확인하십시오.\n"
    "- 다음 조합이 있을 때만 악성으로 간주하십시오:\n"
    "    * 난독화 + 외부 전송\n"
    "    * 사용자 입력 수집 + 외부 전송\n"
    "    * 동적 스크립트 로딩 + 난독화된 URL\n"
    "    * setInterval 또는 무한 루프 + 해시/연산 패턴 (crypto-mining)\n"
    "    * 쿠키/토큰/localStorage 값 → 외부 도메인으로 전송\n\n"

    "최종 출력은 반드시 영어 JSON 형식으로만 작성하십시오.\n"
    "설명 문장도 JSON 내부에서는 영어로 작성해야 합니다.\n\n"

    "출력 형식(STRICT JSON):\n\n"
    "{\n"
    '  "risk_score": 0,\n'
    '  "vulnerabilities": [],\n'
    '  "malicious_behaviors": [],\n'
    '  "pii_threats": [],\n'
    '  "exposed_secrets": [],\n'
    '  "indicators": [],\n'
    '  "verdict": "safe",\n'
    '  "explanation": "short english explanation"\n'
    "}\n\n"
    "JSON 외의 어떤 텍스트도 출력하지 마십시오."
        )

        # ----------------------------
        # SUMMARY PROMPT (문자 그대로)
        # ----------------------------
        self.SUMMARY_PROMPT = (
    "당신은 웹 보안 분석 전문가입니다.\n"
    "아래에는 여러 JavaScript 코드 조각(chunks)에 대한 JSON 분석 결과가 배열 형태로 제공됩니다.\n"
    "이 전체 분석 결과를 종합하여 웹사이트의 최종 보안 평가(총평)를 생성하십시오.\n\n"

    "최종 출력은 반드시 STRICT JSON 형식으로만 작성해야 합니다.\n"
    "JSON 외의 다른 설명, 문장, 주석, 텍스트는 절대 출력하면 안 됩니다.\n\n"

    "출력 형식은 다음과 같습니다:\n"
    "{\n"
    '  "overall_verdict": "safe" 또는 "unsafe",\n'
    '  "total_chunks": 전체 조각 개수(숫자),\n'
    '  "detected_vulnerabilities": [],\n'
    '  "detected_malicious_behaviors": [],\n'
    '  "detected_pii_threats": [],\n'
    '  "exposed_secrets": [],\n'
    '  "score": 0,  // 0~10 범위 정수 점수 (보안 위험도)\n'
    '  "summary_explanation": "여기에 한국어로 된 총평을 작성하십시오."\n'
    "}\n\n"
    "규칙:\n"
    "- 'summary_explanation' 항목은 반드시 한국어로 작성하십시오.\n"
    "- 'score'는 '전체 보안 위험도'를 0~10 정수 점수로 표현하십시오.\n"
    "  (0은 매우 안전 / 10은 극도로 위험)\n"
    "- 키 이름은 영어로 유지하십시오.\n"
    "- JSON 외 텍스트는 절대 출력하지 마십시오.\n"
        )

    # -------- 이하 함수들은 기존 그대로 --------
    def delete_file(self):
        if os.path.isfile(self.gpt_result_path) and os.path.isfile(self.summary_path):
            for a in (self.gpt_result_path, self.summary_path):
                os.remove(a)
                print(f"기존 결과 파일 {a} 삭제 완료 \n")
        
        else:
            for a in (self.gpt_result_path, self.summary_path):
                print(f"기존 결과 파일 {a} 가 존재하지 않습니다.\n")
                continue
            
    
    def openfile(self):
        if os.path.exists(self.combined_txt_path) and os.path.isfile(self.combined_txt_path):
            print(f"{self.combined_txt_path}파일이 존재합니다.")
            try:
                with open(self.combined_txt_path, "r", encoding="utf-8") as f:
                    self.full_code = f.read()
                    print(f"{self.combined_txt_path} 파일 불러오기 성공")
            except Exception as e:
                print(f"ERROR: {e}")
        else:
            print(f"{self.combined_txt_path} 파일이 존재하지 않습니다.")
            sys.exit(1)

    def analyze_file(self):
        print(f"읽은 파일 크기 : {len(self.full_code)}bytes")
        self.chunks = [self.full_code[i:i+self.max_len] for i in range(0, len(self.full_code), self.max_len)]
        print(f"총 {len(self.chunks)} 개 만큼 조각 분할 완료\n")

        total = len(self.chunks)
        for idx, chunk in enumerate(self.chunks, 1):
            print(f"[{idx}/{total}] 조각 이중 분석 중...")
            meaningful_result: str | None = None

            stop_all = False

            for trial in range(2):
                retries = 0
                while retries < 3:
                    try:
                        resp = self.client.chat.completions.create(
                            model=self.model_name,
                            messages=[
                                {"role": "system", "content": self.SYSTEM_PROMPT},
                                {"role": "user", "content": chunk}
                            ],
                            temperature=0.0,
                        )
                        result = (resp.choices[0].message.content or "").strip()
                        print(f"    [시도 {trial+1}] 분석 완료")

                        if result not in ("{}", "", "에러 발생"):
                            meaningful_result = result
                            stop_all = True
                        break

                    except Exception as e:
                        err = str(e)
                        print(f"    [시도 {trial+1}] 분석 실패 (재시도 {retries+1}): {err}")
                        if ("429" in err) or ("rate" in err.lower()) or any(x in err for x in ("502", "503", "504", "timeout", "temporarily", "unavailable")):
                            wait = max(1, 2 ** retries)
                            print(f"      → 제한/일시오류: {wait}초 대기")
                            time.sleep(wait)
                            retries += 1
                        else:
                            meaningful_result = "{}"
                            break

                    time.sleep(0.8)

                if stop_all:
                    break

            self.final_result.append(meaningful_result or "{}")

    @staticmethod
    def _safe_parse_json(text: str):
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except Exception:
            return None

    def save_json_results(self):
        os.makedirs(os.path.dirname(self.gpt_result_path), exist_ok=True)
        json_items = []
        for res in self.final_result:
            parsed = self._safe_parse_json(res)
            json_items.append(parsed if parsed is not None else {"raw": res})

        payload = {"chunks": json_items}
        with open(self.gpt_result_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"[INFO] JSON 저장: {self.gpt_result_path}")

    def summarize_results(self):
        print("[INFO] 전체 요약 생성 중 ....")

        parsed_items = []
        for res in self.final_result:
            parsed = self._safe_parse_json(res)
            if parsed:
                parsed_items.append(parsed)

        resp = self.client.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "system", "content": self.SUMMARY_PROMPT},
                {"role": "user", "content": json.dumps(parsed_items, ensure_ascii=False)}
            ],
            temperature=0.0
        )

        self.summary_result = resp.choices[0].message.content.strip()
        print("[INFO] 종합 요약 완료")

    def summary_save_result(self):
        if not hasattr(self, "summary_result") or not self.summary_result:
            print("[ERROR] 요약 결과가 없습니다. summarize_results()가 먼저 실행되어야 합니다.")
            return

        try:
            parsed = json.loads(self.summary_result)

            with open(self.summary_path, "w", encoding="utf-8") as f:
                json.dump(parsed, f, ensure_ascii=False, indent=2)

            print(f"[INFO] 종합 요약본 저장 성공 → {self.summary_path}")

        except Exception as e:
            print(f"[ERROR] 요약본 저장 실패: {e}")

    def open_result_file(self):
        if os.path.isfile(self.summary_path) and os.path.exists(self.summary_path):
            print(f"{self.summary_path}파일이 존재합니다.")
            with open(self.summary_path, "r", encoding="utf-8") as f:
                result_date = f.read()
                print(result_date)
        else:
            print(f"{self.summary_path}가 존재하지 않습니다.")
            pass    #반복문 이 아니기 때문에 pass로 진행 (continue, break로 들어가면 안됨 )


if __name__ == "__main__":
    LLM = GPTJavaScriptScanner()
    LLM.delete_file()
    LLM.openfile()
    LLM.analyze_file()
    LLM.save_json_results()
    LLM.summarize_results()
    LLM.summary_save_result()
    LLM.open_result_file()