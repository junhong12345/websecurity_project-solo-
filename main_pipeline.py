import os, re, sys, time, json, random
import threading
import requests

from UrlLoader import UrlLoader
from Logic1 import Logic1
from GPT_JS_scanner import GPTJavaScriptScanner
from GPT_HTML_scanner import GPTHTMLScanner
from Logic4 import Logic4
from Result import Result
from delete_programe import Delete
from GPTRiskInterpreter import GPTRiskInterpreter
from DB import DB
from Make_PDF_file import Make_PDF_file

def main():
    url = input("분석할 URL링크를 입력하세요.: ").strip()
    if not url.startswith("http"):
        url = "https://" + url 
    
    if not url:
        print(f"URL을 입력하지 않았습니다. 프로그램을 종료합니다.\n")
        sys.exit(1)

    #delete programe 기능 
    print("기존 결과 자동 삭제 프로그램 실행 시작")
    try:
        delete = Delete()
        delete.delete_file()
    except Exception as e:
        print(f"ERROR: {e}")

    print("\n[1/5] UrlLoader 실행 시작")
    try:
        loader = UrlLoader(url)
        loader.download_page_resources() 
        loader.extract_javascript()        # JS 코드 추출
        loader.scan_steganography() 


        print("스크린샷 저장 완료")

        
    except Exception as e:
        print(f"[1/5] Url Loader ERROR: {e}")

    print("[1/5] UrlLoader 실행 종료")

    print("[2/5] Logic1 - HTTP 프로토콜 헤더 안전성 검사 탐지 기능 실행 시작")
    try:
        L1 = Logic1(url)
        L1.delete_file()
        L1.analyze_url()
        L1.analyze_security_headers()
        L1.save_results()
        L1.openfile()

    except Exception as e:
        print(f"[2/5]Logic1 ERROR: {e}")

    print("[2/5] Logic1  - HTTP 프로토콜 헤더 안전성 검사 탐지 기능 실행 종료")

    #JS scanner 탐지 기능 
    print("[3/5] GPT_JS_scanner 탐지 기능 실행 시작 ")
    try:
        LLM = GPTJavaScriptScanner()
        LLM.delete_file()
        LLM.openfile()
        LLM.analyze_file()
        LLM.save_json_results()
        LLM.summarize_results()
        LLM.summary_save_result()
        LLM.open_result_file()
    except Exception as e:
        print(f"[3/5]GPT_JS_scanner ERROR: {e}")

    print("[3/5] GPT_JS_scanner 탐지 기능 실행 종료 ")
    
    #HTML scanner 탐지 기능 
    print("[4/5] GPT_HTML_scanner 탐지 기능 실행 시작")
    try:
        LLM_html = GPTHTMLScanner()
        LLM_html.delete_file()
        LLM_html.openfile()
        LLM_html.analyze_file()
        LLM_html.save_html_results()
        LLM_html.summarize_results()
        LLM_html.summary_save_result()
        LLM_html.open_result_file()
    except Exception as e:
        print(f"[4/4] GPT_HTML_scanner ERROR: {e}")

    #Logic4탐지 기능 
    print("[5/5] Logic4 탐지 기능 실행 시작")
    try:
        L4 = Logic4()
        L4.delete_result_file()
        L4.open_cookies_file()
        L4.analyze_cookies_file()
        L4.open_storage_file()
        L4.analyze_storage_file()
        L4.save_cookies_result()
        L4.save_storage_result()
        L4.open_result_file()
    except Exception as e:
        print(f"[5/5] Logic4 ERROR: {e}")

    #Result 기능 
    print(" 결과 종합 프로그램 실행 시작 ")
    try:
        result = Result()
        result.merge_txt_files()
        result.merge_json_files()
    except Exception as e:
        print(f"ERROR: {e}")
    print(" 결과 종합 프로그램 종료 ")
    
    #Logic5 웹 사이트 보안 분석 종합 결과 출력 기능 
    print("웹사이트 결과 종합 및 어드바이스 기능 실행 시작 ")
    try:
        LLM_risk_interpreter = GPTRiskInterpreter()
        LLM_risk_interpreter.openfile()
        LLM_risk_interpreter.analysis_json_file()
        LLM_risk_interpreter.analysis_txt_file()
        LLM_risk_interpreter.json_save_analysis_result()
        LLM_risk_interpreter.txt_save_analysis_result()
    except Exception as e:
        print(f"ERROR: {e}")
    print("웹사이트 결과 종합 및 어드바이스 기능 종료")
    # PDF 보고서 생성
    print("PDF 보고서 생성 시작")

    try:
        PDF = Make_PDF_file()
        PDF.delete_file()
        PDF.openfile()
        PDF.make_pdf()
        PDF.save_report()
        PDF.make_pdf_file()

    except Exception as e:
        print(f"PDF ERROR: {e}")

    print("PDF 보고서 생성 종료")

    #DB 저장 프로그램 
    print("DB저장 프로그램 시작 ")
    try:
        database = DB()
        database.save_result_to_db(url)

    except Exception as e:
        print(f"ERROR: {e}")

    


    #분석 종료 
    print("분석 종료")

if __name__ =="__main__":
    main()
