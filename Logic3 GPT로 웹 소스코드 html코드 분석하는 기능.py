#Logic3 GPT로 웹 소스코드 html코드 분석하는 기능 

import os, re, sys, time, json 

import requests
from openai import OpenAI

# --- stdout/stderr 인코딩 (환경 따라 생략 가능) ---
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

class GPTHTMLScanner():
    def __init__(self):
        self.content = None
        self.result = ''
        self.final_result: list[str] = []

        #path
        self.total_path = "/root/project"
        self.downloaded_path = os.path.join(self.total_path, "downloaded")
        self.index_html_path = os.path.join(self.downloaded_path, "index.html")
        self.combined_txt_path = os.path.join(self.downloaded_path, "combined.txt")
        self.api_path = os.path.join(self.total_path, "api_key")
        
        #result path
        self.gpt_result_path = os.path.join(self.total_path, "gpt_html_result.json")
        self.gpt_result_path_txt_path = os.path.join(self.total_path, "gpt_html_result.txt")
        self.max_len = 50000
        self.full_code = ''
        self.chunks: list[str] = []
        self.summary_path = os.path.join(self.total_path, "gpt_html_summary.json")


        api_key_path = os.path.join(self.api_path, "api_key.txt")
        if os.path.isfile(api_key_path):
            try:
                with open(api_key_path, "r", encoding="utf-8") as f:
                    self.api_key =  f.read().strip()
                    print(f"[INFO] api_key 읽기 성공")

            except Exception as e:
                print(f"ERROR: {e}")

        else:
            print(f"{api_key_path}파일을 찾을 수 없습니다.\n")
            print("프로그램을 종료합니다.")
            sys.exit(1) 

        self.client = OpenAI(api_key = self.api_key)
        self.model_name = "gpt-4o-mini"

        self.SYSTEM_PROMPT = (
    "당신은 HTML·DOM 기반 웹 보안 분석 전문가입니다.\n"
    "아래에 제공되는 전체 HTML 코드(index.html)를 기반으로 "
    "취약점, 악성 행위, 외부 리소스 조작, 메타 리다이렉트, 인라인 스크립트 위험 여부 등을 "
    "정적 분석 방식으로 모두 조사하십시오.\n\n"

    "분석 항목은 다음과 같습니다.\n\n"

    "1. HTML 기반 취약점(Vulnerabilities)\n"
    "   - HTML Injection 또는 DOM 기반 XSS 가능성\n"
    "   - unsafe inline event handlers (onclick, onload 등)\n"
    "   - form 태그의 action 조작 / 입력값 검증 부족 구조\n"
    "   - meta refresh 또는 meta redirect\n"
    "   - iframe을 통한 피싱 / clickjacking 위험\n"
    "   - 외부 스크립트(src, href)에 대한 의심스러운 도메인 접근\n"
    "   - mixed content(HTTPS 사이트에서 http 리소스 불러오기)\n\n"

    "2. 악성 동작(Malicious Behavior)\n"
    "   - phishing UI 패턴 (로그인 폼 위장, 은행/결제 UI 패턴 등)\n"
    "   - CSS/HTML을 이용한 숨김형 입력 필드(hidden phishing)\n"
    "   - base64/전체 암호화된 HTML 구조\n"
    "   - auto-submit 또는 자동 리디렉션(form.submit(), meta refresh)\n\n"

    "3. 민감정보 노출(Exposed Secrets)\n"
    "   - 하드코딩된 민감 데이터(API key, token)\n"
    "   - 서버 경로 노출(/internal, /config 등)\n\n"

    "정상 패턴(단독으로는 악성 근거가 아님):\n"
    "------------------------------------------\n"
    "다음 항목들은 정상 HTML에서도 매우 흔하므로 단독으로 악성으로 판단하지 마십시오.\n"
    "1) <script src='...'> 형태의 외부 스크립트 로딩\n"
    "2) CSS 파일 로드(link href='...')\n"
    "3) 정상적인 사이트 분석 도구: Google Analytics, Meta Pixel, Cloudflare\n"
    "4) 사용성 향상을 위한 inline 이벤트 핸들러(onclick 등) — 단, 데이터 제출/전송과 결합될 때만 위험\n"
    "5) iframe 광고 또는 유튜브/구글 지도 삽입\n\n"

    "위험 판정 규칙:\n"
    "------------------------------------------\n"
    "- '특정 패턴이 있다'만으로 악성이라고 판단하지 마십시오.\n"
    "- 반드시 '데이터 유출', 'UI 위장', '자동 리디렉션', '민감 입력값 제출', '의심 도메인과 결합' 같은 "
    "실제 악성 흐름(flow)이 존재할 때만 악성으로 판단하십시오.\n\n"

    "최종 출력은 반드시 STRICT JSON 형식으로만 작성하십시오.\n"
    "설명 문장도 JSON 내부에서는 영어로 작성해야 합니다.\n\n"

    "{\n"
    '  "risk_score": 0,\n'
    '  "vulnerabilities": [],\n'
    '  "malicious_behaviors": [],\n'
    '  "exposed_secrets": [],\n'
    '  "indicators": [],\n'
    '  "verdict": "safe",\n'
    '  "explanation": "short english explanation"\n'
    "}\n\n"
    "JSON 외의 어떤 텍스트도 출력하지 마십시오."
)

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

    def delete_file(self):
        if os.path.isfile(self.gpt_result_path) and os.path.isfile(self.summary_path):
            for a in (self.gpt_result_path, self.summary_path):
                os.remove(a)
                print(f"기존 결과 파일 {a} 삭제 완료 \n")

        else:
            for a in (self.gpt_result_path, self.summary_path):
                print(f"기존 결과 파일 {a}가 존재하지 않습니다.\n")
                continue

    def openfile(self):
        if os.path.isfile(self.index_html_path) and os.path.exists(self.index_html_path):
            print(f"{self.index_html_path}파일이 존재합니다.")
            try:
                with open(self.index_html_path, "r", encoding="utf-8") as f:
                    self.full_code = f.read()
                    print(f"{self.index_html_path} 파일 불러오기 성공")
            except Exception as e:
                print(f"ERROR: {e}")

        else:
            print(f"{self.index_html_path} 파일이 존재하지 않습니다.")
            sys.exit(1)

    def analyze_file(self):
        print(f"읽은 파일 크기: {len(self.full_code)}bytes")
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
                            temperature=0.0
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
        
    def save_html_results(self):
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
            pass #반복문 이 아니기 때문에 pass로 진행 (continue, break로 들어가면 안됨 )


if __name__=="__main__":
    LLM_html = GPTHTMLScanner()
    LLM_html.delete_file()
    LLM_html.openfile()
    LLM_html.analyze_file()
    LLM_html.save_html_results()
    LLM_html.summarize_results()
    LLM_html.summary_save_result()
    LLM_html.open_result_file()
