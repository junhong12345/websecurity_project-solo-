#FAST API
#main.py
import asyncio
import os, re, sys, time, json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, JSONResponse
from starlette.staticfiles import StaticFiles

# ===== 경로 설정 =====
BASE_DIR = Path("/root/project")
PIPELINE = BASE_DIR / "main_pipeline.py"
PYTHON = "python3"  # venv 절대경로를 쓰고 싶으면 교체

# ===== 결과 경로 ======
FINAL_TXT_RESULT = BASE_DIR / "LLM_txt_result.txt"
FINAL_JSON_RESULT = BASE_DIR / "LLM_json_reuslt.json"
SHOT_FILE = BASE_DIR / "downloaded" / "screenshot.png"
DOWNLOADED_DIR = BASE_DIR / "downloaded"

IDLE_TIMEOUT = 150

app =  FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
)



# 헬스체크(선택)
@app.get("/", response_class=PlainTextResponse)
async def root():
    return "OK"
@app.get("/healthz", response_class=PlainTextResponse)
async def healthz():
    return "ok"

def read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            obj = json.load(f)
            return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}

async def run_pipeline_and_stream(url: str, ws: WebSocket):

    env = os.environ.copy()
    proc = await asyncio.create_subprocess_exec(
        PYTHON, "-u", str(PIPELINE),
        cwd=str(BASE_DIR),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=env,
    )

    # URL 바로 주입
    try:
        proc.stdin.write((url + "\n").encode())
        await proc.stdin.drain()
        await ws.send_text(json.dumps({
            "type": "log",
            "message": f"[WS] URL 전달: {url}"
        }, ensure_ascii= False))
    except Exception as e:
        await ws.send_text(json.dumps({
            "type": "log",
            "message": f"[WS] URL 주입 실패: {e}"
        }))

    last_activity = asyncio.get_event_loop().time()

    async def reader():
        nonlocal last_activity
        while True:
            line = await proc.stdout.readline()
            if not line:
                break

            txt = line.decode(errors="ignore").rstrip()
            last_activity = asyncio.get_event_loop().time()

            await ws.send_text(json.dumps({
                "type": "log",
                "message": txt
            }, ensure_ascii= False))

    # reader()를 별도 태스크로 실행
    reader_task = asyncio.create_task(reader())

    # idle 타이머 + 종료 대기
    while True:
        if reader_task.done():
            break

        await asyncio.sleep(1)
        if asyncio.get_event_loop().time() - last_activity > IDLE_TIMEOUT:
            await ws.send_text(f"[WS] {IDLE_TIMEOUT}s 무응답 → 파이프라인 종료")
            try:
                proc.kill()
            except:
                pass
            break

    rc = await proc.wait()
    return rc


# ======== WS 엔드포인트 =============
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()   # ★ 없으면 403 뜸

    print("[WS] 클라이언트 연결됨")

    try:
        while True:
            msg = await websocket.receive_text()
            data = json.loads(msg)

            if data.get("action") == "analyze":
                url = data.get("url")
                await websocket.send_text(json.dumps({
                    "type": "log",
                    "message": f"[WS] 분석 시작: {url}"
                }, ensure_ascii= False))

                # 파이프라인 실행
                await run_pipeline_and_stream(url, websocket)

    except WebSocketDisconnect:
        print("[WS] 클라이언트 연결 종료")


# ======= REST API: TXT 파일 결과 조회
@app.get("/get-txt", response_class=PlainTextResponse)
def get_txt():
    target = FINAL_TXT_RESULT

    if not target.exists():
        return PlainTextResponse("[INFO] 최종 결과 TXT 파일이 존재하지 않습니다.", status_code=404)

    try:
        text = target.read_text(encoding="utf-8", errors="ignore")
        return PlainTextResponse(
            text,
            media_type="text/plain; charset=utf-8"
        )
    except Exception as e:
        return PlainTextResponse(f"[ERROR] TXT 파일 읽기 실패: {e}", status_code=500)

#========REST API: JSON 파일 결과 조회
@app.get("/get-json")
def get_json():
    target = FINAL_JSON_RESULT

    if not target.exists():
        return JSONResponse(
            {"error": "최종 결과 JSON 파일이 존재하지 않습니다."},
            status_code=404
        )

    try:
        data = json.loads(target.read_text(encoding="utf-8", errors="ignore"))
        return JSONResponse(
            data,
            media_type="application/json; charset=utf-8"
        )
    except Exception as e:
        return JSONResponse(
            {"error": f"JSON 파일 읽기 실패: {e}"},
            status_code=500
        )

from fastapi.responses import FileResponse

@app.get("/get-screenshot")
def get_screenshot():
    target = SHOT_FILE

    if not target.exists():
        return PlainTextResponse("[INFO] 스크린샷 없음", status_code=404)

    return FileResponse(
        target,
        media_type="image/png",
        filename="screenshot.png"
    )

from fastapi.responses import FileResponse
@app.get("/download-pdf")
def download_pdf():
    pdf_path="/root/project/website_security_report.pdf"
    return FileResponse(
        path=pdf_path,
        media_type="application/octet-stream",
        filename="website_security_report.pdf"
    )
