import os
import re
import sys
import time
import json
import requests
import reportlab    #pdf file 만드는 python 라이브러리 

from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from pathlib import Path
from openai import OpenAI


class Make_PDF_file:
    def __init__(self):
        self.content = None
        self.result = None
        self.final_result = []

        # Path
        self.base_path = Path("/root/project")

        self.api_path = self.base_path / "api_key"
        self.api_key_path = self.api_path / "api_key.txt"

        self.total_txt_result_path = self.base_path / "total_txt_result.txt"
        self.total_json_result_path = self.base_path / "total_json_result.json"

        self.report_path = self.base_path / "website_security_report.md"
        self.report_pdf_path = self.base_path / "website_security_report.pdf"

        # System Prompt
        self.SYSTEM_PROMPT = """
당신은 10년 이상의 경력을 가진 웹 보안 진단 전문 컨설턴트이다.

입력으로 제공되는 JSON은 웹사이트 자동 보안 진단 시스템의 최종 분석 결과이다.

당신의 역할은 새로운 사실을 추측하거나 임의로 생성하는 것이 아니라,
입력된 분석 결과만을 근거로 전문적인 보안 진단 보고서를 작성하는 것이다.

다음 규칙을 반드시 따른다.

1. 입력 JSON에 존재하는 정보만 사용한다.
2. 존재하지 않는 취약점이나 분석 결과를 추가하지 않는다.
3. 기술적인 내용은 객관적이고 전문적인 문체로 작성한다.
4. 보고서는 PDF로 변환될 예정이므로 Markdown 형식으로 작성한다.
5. 표(Table)를 적극적으로 활용한다.
6. 각 항목은 충분한 설명을 포함하여 작성한다.
7. AI가 작성했다는 표현은 절대 사용하지 않는다.

보고서는 반드시 아래 순서를 따른다.

# Website Security Analysis Report

## 1. Executive Summary
- 분석 대상 URL
- 분석 일시
- 전체 위험도
- 종합 점수
- 전체 결과 요약

## 2. Overall Assessment
- 최종 위험도
- 종합 점수
- 주요 발견 사항

## 3. Detailed Analysis

### 3.1 Blacklist Analysis
- 결과
- 설명

### 3.2 Similarity Analysis
- 결과
- 설명

### 3.3 JavaScript Analysis
- 탐지된 주요 행위
- 난독화 여부
- 설명

### 3.4 Network Analysis
- 외부 통신
- 의심 요청
- 설명

### 3.5 Runtime Hook Analysis
- 후킹 여부
- 설명

## 4. Integrated Security Assessment

각 분석 결과를 종합하여 전체적인 위험도를 설명한다.

## 5. Security Recommendations

최소 5개의 보안 권고사항을 작성한다.

## 6. Final Verdict

최종 위험도와 관리자가 취해야 할 조치를 작성한다.

보고서 안에는 반드시 아래 표를 포함한다.

| Module | Status | Risk | Summary |
|--------|--------|------|---------|

Status는 PASS / WARNING / DANGER만 사용한다.

Risk는 Low / Medium / High / Critical만 사용한다.

입력되는 JSON만 근거로 보고서를 작성한다.
"""

        # API Key
        with open(self.api_key_path, "r", encoding="utf-8") as f:
            self.api_key = f.read().strip()

        self.client = OpenAI(api_key=self.api_key)
        self.model_name = "gpt-4o-mini"
    def delete_file(self):
        try:
            if os.path.isfile(self.report_path) and os.path.exists(self.report_path):
                print(f"{self.report_path} 파일이 존재합니다.\n")
                os.remove(self.report_path)
            else:
                print(f"{self.report_path} 파일이 존재하지 않습니다.\n")

            if os.path.isfile(self.report_pdf_path) and os.path.exists(self.report_pdf_path):
                print(f"{self.report_pdf_path} 파일이 존재합니다.\n")
                os.remove(self.report_pdf_path)
            else:
                print(f"{self.report_pdf_path}파일이 존재하지 않습니다.\n")


            print("기존 보고서 결과 파일 삭제 완료\n")

        except Exception as e:
            print(f"ERROR: {e}")

    def openfile(self):
        try:

            with open(self.total_json_result_path, "r", encoding="utf-8") as f:
                self.json_content = json.load(f)

            print("[INFO] JSON 로드 완료")

            with open(self.total_txt_result_path, "r", encoding = "utf-8") as f:
                self.txt_content = f.read()

            print("[INFO] TXT 로드 완료")
        except Exception as e:
            print(f"ERROR: {e}")
    
    def make_pdf(self):
        try:
            user_prompt = (
                "다음은 웹 보안 진단 시스템의 최종 분석 결과이다.\n\n"
                "[JSON RESULT]\n"
                f"{json.dumps(self.json_content, ensure_ascii=False, indent=2)}\n\n"
                "[TEXT RESULT]\n"
                f"{self.txt_content}\n\n"
                "위 결과를 기반으로 전문적인 Website Security Analysis Report를 작성하시오."
            )

            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": self.SYSTEM_PROMPT
                    },

                    {
                        "role": "user",
                        "content": user_prompt
                    }
                ],

                temperature=0,
                max_completion_tokens=5000
            )

            self.result = response.choices[0].message.content.strip()

            if self.result.startswith("```"):
                self.result = re.sub(r"^```[a-zA-Z]*\n?", "", self.result)
                self.result = re.sub(r"\n?```$", "", self.result).strip()

            print("[INFO] GPT 보고서 생성 완료")

        except Exception as e:
            print(f"ERROR: {e}")


    def make_pdf_file(self):
        try:
            pdf_path = self.base_path / "website_security_report.pdf"

            # 사용할 폰트 등록 (리눅스 경로 예시)
            font_path = "/usr/share/fonts/truetype/nanum/NanumGothic.ttf"

            if os.path.exists(font_path):
                pdfmetrics.registerFont(TTFont("Nanum", font_path))
                styles = getSampleStyleSheet()
                styles["BodyText"].fontName = "Nanum"
                styles["Heading1"].fontName = "Nanum"
                styles["Heading2"].fontName = "Nanum"
                styles["Heading3"].fontName = "Nanum"
                style = styles["BodyText"]

            else:
                print("[WARNING] NanumGothic.ttf가 없어 기본 폰트를 사용합니다.")
                style = getSampleStyleSheet()["BodyText"]
            doc = SimpleDocTemplate(str(pdf_path))
            story = []

            for line in self.result.split("\n"):

                if line.strip() == "":
                    continue

                line = line.replace("&", "&amp;")
                line = line.replace("<", "&lt;")
                line = line.replace(">", "&gt;")
                story.append(Paragraph(line, style))

            doc.build(story)
            print(f"[INFO] PDF 생성 완료 : {pdf_path}")

        except Exception as e:
            print(f"ERROR : {e}")

    def save_report(self):
        try:
            if not self.result:
                print("[ERROR] 저장할 보고서가 없습니다.")

                return

            

            with open(self.report_path, "w", encoding="utf-8") as f:
                f.write(self.result)

            print(f"[INFO] Markdown 보고서 저장 완료 : {self.report_path}")

        except Exception as e:
            print(f"ERROR: {e}")


if __name__ == "__main__":
    PDF = Make_PDF_file()
    PDF.delete_file()
    PDF.openfile()
    PDF.make_pdf()
    PDF.save_report()
    PDF.make_pdf_file()
