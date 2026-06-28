# websecurity_project-solo-

Flow chart

<img width="9547" height="32768" alt="Frame 19" src="https://github.com/user-attachments/assets/ea35762a-db15-4858-9f54-bab40e9ad846" />

🔍 Web Site Security Vulnerability Detection System

Overview

본 프로젝트는 웹 사이트의 다양한 보안 요소를 자동으로 분석하여 취약점을 탐지하고, 최종적으로 보안 진단 보고서(PDF) 를 생성하는 웹 보안 진단 시스템이다.

사용자는 웹 사이트 URL만 입력하면 HTTP 보안 헤더, JavaScript, HTML, Cookie, LocalStorage 등을 자동으로 분석할 수 있으며, GPT 기반 분석을 통해 사람이 읽기 쉬운 보안 보고서를 제공한다.

Features

HTTP Security Header Analysis

* HTTP Security Header 분석
* 보안 헤더 누락 여부 탐지
* Header 설정 상태 분석

JavaScript Security Analysis

* JavaScript 코드 자동 추출
* 난독화 코드 분석
* 위험 API 사용 여부 탐지
* GPT 기반 JavaScript 보안 분석

  HTML Structure Analysis

* HTML 구조 분석
* 피싱 의심 요소 탐지
* 숨겨진 입력값 분석
* GPT 기반 HTML 분석

⸻

Cookie & Storage Analysis

* Cookie 분석
* LocalStorage 분석
* SessionStorage 분석
* 민감정보 저장 여부 탐지

⸻

Screenshot Collection

* 대상 웹 사이트 스크린샷 자동 수집

⸻

Security Report Generation

최종 분석 결과를 기반으로

* Markdown 보고서 생성
* PDF 보고서 생성
* 종합 위험도 평가
* 보안 권고사항 제공

System Architecture
User
   │
   ▼
Frontend (HTML / CSS / JavaScript)
   │
   ▼
FastAPI Backend
   │
   ▼
main_pipeline.py
   │
   ├──────── UrlLoader
   │
   ├──────── Logic1
   │
   ├──────── GPT JavaScript Scanner
   │
   ├──────── GPT HTML Scanner
   │
   ├──────── Logic4
   │
   ├──────── Result Merge
   │
   ├──────── GPT Risk Interpreter
   │
   ├──────── PDF Report Generator
   │
   └──────── Database


 Detection Modules

| Module | Description |
|:-------|:------------|
| **UrlLoader** | Collects website resources and captures screenshots. |
| **Logic1** | Analyzes HTTP security headers and detects missing or insecure configurations. |
| **GPT JavaScript Scanner** | Performs AI-based JavaScript security analysis, including malicious behavior and obfuscation detection. |
| **GPT HTML Scanner** | Analyzes HTML structure to identify suspicious elements and phishing-related patterns. |
| **Logic4** | Inspects Cookies, LocalStorage, and SessionStorage for insecure data storage. |
| **Result** | Integrates analysis results from all detection modules into a unified output. |
| **GPT Risk Interpreter** | Generates an overall security assessment and provides risk interpretation using AI. |
| **PDF Generator** | Generates a professional security analysis report in Markdown and PDF formats. |
| **Database** | Stores analysis results and generated reports for future reference. |


   Technologies

Backend

* Python
* FastAPI
* OpenAI API
* ReportLab

⸻

Frontend

* HTML
* CSS
* JavaScript

⸻

Database

* SQLite

⸻

AI

* GPT-4o-mini

Generated Outputs

프로그램 실행 후 다음과 같은 결과가 생성된다.
LLM_txt_result.txt

LLM_json_result.json

website_security_report.md

website_security_report.pdf

screenshot.png
