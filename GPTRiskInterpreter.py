import os, re,sys, time, json 

import requests
from openai import OpenAI

# --- stdout/stderr 인코딩 (환경 따라 생략 가능) ---
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

class GPTRiskInterpreter:
    def __init__(self):
        self.json_content = None
        self.txt_content =None
        self.result = []

        #path 
        self.total_path = "/root/project"
        self.downloaded_path = os.path.join(self.total_path, "downloaded")
        self.json_data = os.path.join(self.total_path, "total_json_result.json")
        self.txt_data = os.path.join(self.total_path, "total_txt_result.txt")

        self.api_path = os.path.join(self.total_path, "api_key")

        #result path 
        self.json_final_result: list[str] = []
        self.txt_final_result: list[str] = []
        self.json_final_result_path = os.path.join(self.total_path, "LLM_json_reuslt.json")
        self.txt_final_result_path = os.path.join(self.total_path, "LLM_txt_result.txt")

        self.max_len = 50000
        self.full_code = ""
        self.chunks: list[str] = []

        api_key_path  = os.path.join(self.api_path, "api_key.txt")
        if os.path.isfile(api_key_path):
            try:
                with open(api_key_path, "r", encoding="utf-8") as f:
                    self.api_key = f.read().strip()     #앞 뒤 공백 삭제
                    print(f"[INFO] api_key 읽기 성공")
            except Exception as e:
                print(f"ERROR : {e}")
        else:
            print(f"{api_key_path}파일을 찾을 수 없습니다.\n")
            print("프로그램을 종료합니다.")
            sys.exit(1)

        self.client = OpenAI(api_key = self.api_key)
        self.model_name = "gpt-4o-mini"

        self.JSON_SYSTEM_PROMPT = """       
너는 웹 보안 전문가이며,
자동 분석 엔진이 생성한 결과를
“증거 기반·비단정 원칙”으로 해석하는
보안 리뷰어다.

입력으로 제공되는 JSON 데이터는
취약점 판정 결과가 아니라,
HTML, JavaScript, HTTP 보안 헤더, 정책 설정에 대한
정적·구조적 분석 결과이다.

이 데이터에는
실제 공격 발생 여부,
민감정보의 실제 유출 여부,
악성 행위의 성공 여부는 포함되어 있지 않다.

────────────────────────
[절대 판단 원칙]
아래 원칙은 반드시 모두 지켜야 한다.

1. 탐지된 패턴의 존재만으로 취약점을 단정하지 않는다.
2. 공격 성공, 공격 가능, 실제 악용을 전제로 서술하지 않는다.
3. 입력 데이터에 명시되지 않은 사실을 추론하지 않는다.
4. “탈취”, “유출”, “공격 가능”이라는 표현을 사용하지 않는다.
5. 공격자는 존재한다고 가정하지 않는다.
6. 네트워크 환경(Wi-Fi, MITM 등)을 가정하지 않는다.
7. 사용자의 행동을 가정하지 않는다.
8. 서버 측 보안 로직의 존재 여부를 추측하지 않는다.
9. 민감정보가 실제로 존재한다고 단정하지 않는다.
10. 쿠키 값의 의미를 해석하지 않는다.
11. 코드가 실행된다고 가정하지 않는다.

11-1. 쿠키가 민감정보를 포함한다고 판단하지 않는다.
11-2. 쿠키의 값, 목적, 의미를 추가로 해석하지 않는다.
11-3. 세션 식별자(JSESSIONID, SESSIONID)는 민감정보로 분류하지 않는다.
11-4. 입력 데이터에 "민감정보"라는 표현이 명시적으로 존재하지 않으면
      해당 용어를 출력에 사용하지 않는다.

12. 정책 미설정을 즉시 보안 사고로 연결하지 않는다.
13. 대형 서비스, 소형 서비스와 같은 규모 분류를 하지 않는다.
14. “일반적으로”, “보통”, “등”과 같은 표현을 사용하지 않는다.
15. 공격 명칭은 기술적 연관성 설명에만 사용한다.
16. 위험도(HIGH, MEDIUM)를 그대로 반복하지 않는다.
17. 개선 필요성은 “권고” 수준으로만 제시한다.
18. 입력 데이터로 증명되지 않은 인과관계를 만들지 않는다.
19. 하나의 패턴을 여러 공격 시나리오로 확장하지 않는다.
20. 보안 미성숙, 취약함과 같은 정성적 평가를 하지 않는다.
21. 판단은 항상 “구조적 신호” 기준으로만 수행한다.
22. 모든 서술은 입력 데이터의 범위를 벗어나지 않는다.

────────────────────────
[판단 분류 기준]

- 구조적 신호:
  설계 또는 설정 측면에서
  보안 검토가 필요한 상태

- 조건부 주의:
  특정 추가 조건이 충족될 경우
  보안 영향이 커질 수 있는 상태

- 명확한 취약점:
  입력 데이터만으로
  공격 성립이 증명된 경우
  (본 데이터에는 일반적으로 해당 없음)

────────────────────────
[작업 절차]

[1단계] 전체 보안 상태 요약
- 구조적으로 안정적인 부분과
  주의가 필요한 부분을 구분하여 요약한다.
- 단정적인 표현을 사용하지 않는다.

[2단계] 긍정적 보안 요소 정리
- HTTPS 사용
- 보안 헤더 존재
- 정책 기반 설정
- 분리된 구조
입력 데이터로 확인 가능한 항목만 서술한다.

[3단계] 탐지된 패턴 해석
- 각 패턴이 의미하는 구조적 특성을 설명한다.
- 설계상 선택일 가능성을 함께 제시한다.
- 공격 성립을 전제로 하지 않는다.

[4단계] 보안 영향 범위 설명
- 해당 패턴이 영향을 줄 수 있는
  보안 영역을 제한적으로 설명한다.
- 조건이 필요한 경우 명확히 조건부로 서술한다.

[5단계] 종합 판단
- 아래 중 하나로만 결론을 제시한다.
  ▪ 양호
  ▪ 관리 필요
  ▪ 개선 권장

────────────────────────
[출력 규칙]

- 추측 금지
- 과장 금지
- 공격 시나리오 생성 금지
- 입력 데이터 기반 서술 유지
- 보고서 형식의 한국어 문장 사용
""" 
        self.TXT_SYSTEM_PROMPT = """
너는 웹 보안 전문가이며,
클라이언트 저장소 및 쿠키 분석 결과를
“신호 기반·비단정 원칙”으로 해석하는
보안 리뷰어다.

입력으로 제공되는 TXT 데이터는
쿠키, 로컬 스토리지, 세션 스토리지에서
탐지된 설정 상태 및 보안 신호 목록이다.

이 데이터는
실제 취약점 판정이 아니며,
공격 발생 여부를 포함하지 않는다.

────────────────────────
[절대 판단 원칙]

1. 위험 신호를 공격으로 연결하지 않는다.
2. 공격자가 존재한다고 가정하지 않는다.
3. 실제 데이터 탈취를 전제로 서술하지 않는다.
4. 민감정보가 저장되어 있다고 단정하지 않는다.
5. 저장된 값의 의미를 해석하지 않는다.
6. 쿠키가 민감정보를 포함한다고 판단하지 않는다.
7. 세션 식별자(JSESSIONID, SESSIONID)는 민감정보로 분류하지 않는다.
8. 입력 데이터에 "민감정보"라는 표현이 명시적으로 존재하지 않으면
   해당 용어를 사용하지 않는다.
9. 공격 성공 가능성을 언급하지 않는다.
10. “위험”, “취약”이라는 표현을 남용하지 않는다.
11. 공격 명칭은 기술적 연관성 설명에만 사용한다.
12. HIGH, MEDIUM 표기를 그대로 반복하지 않는다.
13. 사용자 행동을 가정하지 않는다.
14. 서버 검증 로직을 추측하지 않는다.
15. 네트워크 공격을 가정하지 않는다.
16. 환경 설정 누락을 즉시 사고로 연결하지 않는다.
17. 여러 신호를 하나의 공격으로 묶지 않는다.
18. “등”, “일반적으로” 같은 표현을 사용하지 않는다.
19. 실무 리뷰 관점에서만 서술한다.
20. 개선은 권고 수준으로만 제시한다.
21. 구조적 신호와 사고를 명확히 분리한다.
22. 입력 데이터 범위를 초과하지 않는다.
23. 모든 판단은 조건부 표현을 기본으로 한다.
24. 단정적 결론을 피한다.
25. 설명은 간결하고 명확하게 작성한다.

────────────────────────
[작업 절차]

[1단계] 신호의 의미 설명
- 각 항목이 의미하는 설정 상태를 설명한다.
- 공격 성립을 전제로 하지 않는다.

[2단계] 조건부 보안 영향 설명
- 특정 조건이 필요한 경우에만
  조건부로 영향을 설명한다.

[3단계] 신호 수준 재정리
- 구조적 신호
- 주의가 필요한 설정
으로만 재분류한다.

[4단계] 개선 여지 제시
- 필수 수정이 아닌
  보안 강화 관점의 권고로 작성한다.

────────────────────────
[출력 규칙]

- 단정 금지
- 추측 금지
- 공격 시나리오 생성 금지
- 실무 리뷰 톤 유지
- 입력 데이터 기반 설명만 허용
"""     #TXT프롬프트

    def deletefile(self):
        if os.path.isfile(self.json_final_result_path) and os.path.isfile(self.txt_final_result_path):
            for a in(self.json_final_result_path, self.txt_final_result_path):
                os.remove(a)
                print(f"기존 결과 파일 {a} 삭제 완료 \n")
        
        else:
            for a in (self.json_final_result_path, self.txt_final_result_path):
                print(f"기존 결과 파일 {a}가 존재하지 않습니다.\n")
                continue

    def openfile(self):
        if os.path.isfile(self.json_data) and os.path.isfile(self.txt_data):
            print(f"{self.json_data}, {self.txt_data}파일이 존재합니다.")
            try:
                with open(self.json_data, "r", encoding="utf-8") as f:
                    self.json_content = f.read()
                    print(f"{self.json_data} 파일 불러오기 성공")

                with open(self.txt_data, "r", encoding="utf-8") as f:
                    self.txt_content = f.read()
                    print(f"{self.txt_data} 파일 불러오기 성공")

            except Exception as e:
                print(f"ERROR: {e}")
        elif not os.path.isfile(self.json_data):
            print(f"{self.json_data} 파일이 존재하지 않습니다.")
            sys.exit(1)
        elif not os.path.isfile(self.txt_data):
            print(f"{self.txt_data}파일이 존재하지 않습니다.")
            sys.exit(1)
        
    def analysis_json_file(self):
        print(f"읽은 파일 크기: {len(self.json_content)} bytes")
        self.json_chunks = [self.json_content[i:i+self.max_len] for i in range(0, len(self.json_content), self.max_len)]
        print(f"총 {len(self.json_chunks)} 크기 만큼 분할 완료")

        total = len(self.json_chunks)
        for idx, chunk in enumerate(self.json_chunks, 1):
            print(f"[{idx}/{total}] 조각 이중 분석 중...")
            meaningful_result: str | None = None

            stop_all = False

            for trial in range(2):
                retries = 0
                while retries<3:
                    try:
                        resp = self.client.chat.completions.create(
                            model =self.model_name, 
                            messages = [
                                {"role": "system", "content": self.JSON_SYSTEM_PROMPT},
                                {"role": "user", "content": chunk}
                            ],
                            temperature = 0.0
                        )
                        result = (resp.choices[0].message.content or "").strip()
                        print(f"    [시도 {trial+1}]분석 완료")

                        if result not in ("{}", "", "에러 발생"):
                            meaningful_result=result
                            stop_all = True
                        break

                    except Exception as e:
                        err = str(e)
                        print(f"    [시도 {trial+1}] 분석 실패 (재시도 {retries+1}): {err}")
                        if ("429" in err) or ("rate" in err.lower()) or any(x in err for x in ("502", "503", "504", "timeout", "temporarily", "unavailable")):
                            wait = max(1, 2**retries)
                            print(f"      → 제한/일시오류: {wait}초 대기")
                            time.sleep(wait)
                            retries +=1
                        else:
                            meaningful_result = "{}"
                            break
                    time.sleep(0.8)

                if stop_all:
                    break
            
            self.json_final_result.append(meaningful_result or "{}")

        
    def analysis_txt_file(self):
        print(f"읽은 파일 크기: {len(self.txt_content)} bytes")
        self.txt_chunks = [self.txt_content[i:i+self.max_len] for i in range(0, len(self.txt_content), self.max_len)]
        print(f"총 {len(self.txt_chunks)} 개 만큼 조각 분할 완료\n") 

        total  = len(self.txt_chunks)
        for idx, chunk in enumerate(self.txt_chunks, 1):
            print(f"[{idx}/{total}] 조각 이중 분석 중...")
            meaningful_result: str| None =None

            stop_all =False

            for trial in range(2):
                retries =0
                while retries <3:
                    try:
                        resp = self.client.chat.completions.create(
                            model = self.model_name,
                            messages=[
                            {"role": "system", "content": self.TXT_SYSTEM_PROMPT},
                            {"role": "user", "content": chunk}
                            ],
                            temperature = 0.0
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
                            wait = max(1, 2**retries)
                            print(f"      → 제한/일시오류: {wait}초 대기")
                            time.sleep(wait)
                            retries +=1

                        else:
                            meaningful_result = "{}"
                            break
                    
                    time.sleep(0.8)
                
                if stop_all:
                    break 

            self.txt_final_result.append(meaningful_result or "{}")
    
    @staticmethod
    def _safe_parse_json(text: str):
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except Exception:
            return None
        
    def json_save_analysis_result(self):
        json_items = []
        for res in self.json_final_result:
            parsed = self._safe_parse_json(res)
            json_items.append(parsed if parsed is not None else {"raw": res})

        payload = {"chunks": json_items}
        with open(self.json_final_result_path, "w",encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii= False, indent =2)
        print(f"[INFO] 최종 JSON 결과 저장: {self.json_final_result_path}")
    
    def txt_save_analysis_result(self):
        json_items = []
        for res in self.txt_final_result:
            parsed = self._safe_parse_json(res)
            json_items.append(parsed if parsed is not None else {"raw": res})
        
        payload = {"chunks": json_items}
        with open(self.txt_final_result_path, "w", encoding="utf-8") as f:
            json.dump(payload, f,ensure_ascii= False, indent=2)
        print(f"[INFO] 최종 TXT 결과 저장: {self.txt_final_result_path}")

if __name__=="__main__":
    LLM_risk_interpreter = GPTRiskInterpreter()
    LLM_risk_interpreter.openfile()
    LLM_risk_interpreter.analysis_json_file()
    LLM_risk_interpreter.analysis_txt_file()
    LLM_risk_interpreter.json_save_analysis_result()
    LLM_risk_interpreter.txt_save_analysis_result()