import streamlit as st
import base64
import json
import uuid
import requests
import os
import mimetypes
from datetime import datetime
import time
import threading
import io
from PIL import Image

# ページ設定
st.set_page_config(
    page_title="DDS + AI 統合ツール",
    page_icon="🔒",
    layout="wide"
)

st.title("🔒 DDS + AI 統合コンテンツ検査ツール")
st.caption("DDSでポリシー違反をチェック後、AI APIで応答を生成")

# ==================== 初期化 ====================
if "messages" not in st.session_state:
    st.session_state.messages = []
if "txid" not in st.session_state:
    st.session_state.txid = str(uuid.uuid4())
if "filters" not in st.session_state:
    st.session_state.filters = [
        {"id": "c23de41e-f4a7-4b9e-9c1b-5b4eef283ec0", "name": "PCI"},
        {"id": "e58edfb6-bfa2-4256-ae28-ce929ba46bc8", "name": "source code detection"}
    ]
if "dds_configured" not in st.session_state:
    st.session_state.dds_configured = False
if "ai_configured" not in st.session_state:
    st.session_state.ai_configured = False
if "uploaded_file_info" not in st.session_state:
    st.session_state.uploaded_file_info = None
if "file_checked" not in st.session_state:
    st.session_state.file_checked = False
if "file_violations" not in st.session_state:
    st.session_state.file_violations = []
if "file_approved" not in st.session_state:
    st.session_state.file_approved = False
if "file_data" not in st.session_state:
    st.session_state.file_data = None
if "filename" not in st.session_state:
    st.session_state.filename = None
if "ai_api_key" not in st.session_state:
    st.session_state.ai_api_key = "1234"
if "ai_api_url" not in st.session_state:
    st.session_state.ai_api_url = "http://localhost:1234/v1"
if "ai_model" not in st.session_state:
    st.session_state.ai_model = "Qwen3 8B - Q4_K_M"
if "selected_provider" not in st.session_state:
    st.session_state.selected_provider = "ローカル (LM Studio)"
if "debug_mode" not in st.session_state:
    st.session_state.debug_mode = False
if "debug_logs" not in st.session_state:
    st.session_state.debug_logs = []
if "log_counter" not in st.session_state:
    st.session_state.log_counter = 0
if "process_start_time" not in st.session_state:
    st.session_state.process_start_time = None
if "show_debug_panel" not in st.session_state:
    st.session_state.show_debug_panel = False

# ==================== AIプロバイダー設定 ====================
AI_PROVIDERS = {
    "DeepSeek": {
        "url": "https://api.deepseek.com/v1/chat/completions",
        "models": ["deepseek-chat", "deepseek-coder"],
        "default_model": "deepseek-chat",
        "api_key_required": True,
        "description": "DeepSeek API"
    },
    "OpenAI": {
        "url": "https://api.openai.com/v1/chat/completions",
        "models": ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"],
        "default_model": "gpt-3.5-turbo",
        "api_key_required": True,
        "description": "OpenAI API"
    },
    "ローカル (LM Studio)": {
        "url": "http://localhost:1234/v1",
        "models": ["Qwen3 8B - Q4_K_M", "llama3-8b", "mistral-7b", "phi-3", "gemma-2b"],
        "default_model": "Qwen3 8B - Q4_K_M",
        "api_key_required": False,
        "default_api_key": "1234",
        "description": "LM Studio ローカルサーバー"
    },
    "ローカル (Ollama)": {
        "url": "http://localhost:11434/v1/chat/completions",
        "models": ["llama3", "mistral", "phi3", "gemma", "qwen", "llama2", "codellama", "llava"],
        "default_model": "llama3",
        "api_key_required": False,
        "default_api_key": "ollama",
        "description": "Ollama ローカルサーバー"
    },
    "Groq": {
        "url": "https://api.groq.com/openai/v1/chat/completions",
        "models": ["llama3-70b-8192", "llama3-8b-8192", "mixtral-8x7b-32768", "gemma2-9b-it"],
        "default_model": "llama3-70b-8192",
        "api_key_required": True,
        "description": "Groq API"
    }
}

# ==================== MIMEタイプ関数 ====================
def get_mime_type(filename):
    ext = os.path.splitext(filename)[1].lower()
    mime_map = {
        '.txt': 'text/plain', '.csv': 'text/csv', '.log': 'text/plain',
        '.ini': 'text/plain', '.cfg': 'text/plain', '.conf': 'text/plain',
        '.doc': 'application/msword',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.dot': 'application/msword', '.dotx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.template',
        '.docm': 'application/vnd.ms-word.document.macroEnabled.12',
        '.xls': 'application/vnd.ms-excel',
        '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        '.xlsm': 'application/vnd.ms-excel.sheet.macroEnabled.12',
        '.xlsb': 'application/vnd.ms-excel.sheet.binary.macroEnabled.12',
        '.ppt': 'application/vnd.ms-powerpoint',
        '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        '.pptm': 'application/vnd.ms-powerpoint.presentation.macroEnabled.12',
        '.pps': 'application/vnd.ms-powerpoint', '.ppsx': 'application/vnd.openxmlformats-officedocument.presentationml.slideshow',
        '.pdf': 'application/pdf',
        '.eml': 'message/rfc822', '.msg': 'application/vnd.ms-outlook',
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
        '.png': 'image/png', '.gif': 'image/gif',
        '.bmp': 'image/bmp', '.tiff': 'image/tiff', '.tif': 'image/tiff',
        '.webp': 'image/webp', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
        '.zip': 'application/zip', '.7z': 'application/x-7z-compressed',
        '.rar': 'application/vnd.rar', '.tar': 'application/x-tar', '.gz': 'application/gzip',
        '.html': 'text/html', '.htm': 'text/html',
        '.xml': 'text/xml', '.json': 'application/json',
        '.css': 'text/css', '.js': 'application/javascript',
        '.rtf': 'application/rtf',
        '.odt': 'application/vnd.oasis.opendocument.text',
        '.ods': 'application/vnd.oasis.opendocument.spreadsheet',
        '.odp': 'application/vnd.oasis.opendocument.presentation',
    }
    return mime_map.get(ext, 'application/octet-stream')

# ==================== デバッグログ関数 ====================
def add_debug_log(step, message, log_type="info", elapsed_time=None, details=None):
    """デバッグログを追加する関数"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    st.session_state.log_counter += 1
    log_entry = {
        "id": st.session_state.log_counter,
        "timestamp": timestamp,
        "step": step,
        "message": message,
        "type": log_type,
        "elapsed_time": elapsed_time,
        "details": details
    }
    st.session_state.debug_logs.append(log_entry)
    st.session_state.show_debug_panel = True

def clear_debug_logs():
    """デバッグログをクリアする関数"""
    st.session_state.debug_logs = []
    st.session_state.log_counter = 0
    st.session_state.show_debug_panel = False

def render_debug_logs():
    """デバッグログを表示する関数（右パネル用）"""
    if not st.session_state.debug_logs:
        st.info("📋 デバッグログはありません")
        return
    
    # ログ表示
    for log in st.session_state.debug_logs:
        log_id = log["id"]
        timestamp = log["timestamp"]
        step = log["step"]
        message = log["message"]
        log_type = log["type"]
        elapsed = log.get("elapsed_time")
        details = log.get("details")
        
        icon_map = {
            "info": "ℹ️",
            "success": "✅",
            "warning": "⚠️",
            "error": "❌"
        }
        color_map = {
            "info": "#0066cc",
            "success": "#00aa00",
            "warning": "#cc8800",
            "error": "#cc0000"
        }
        
        icon = icon_map.get(log_type, "ℹ️")
        color = color_map.get(log_type, "#0066cc")
        
        time_info = f"🕐 {timestamp}"
        if elapsed is not None:
            time_info += f" | ⏱️ {elapsed:.3f}秒"
        
        # ログ表示
        st.markdown(
            f"""
            <div style="
                border-left: 3px solid {color};
                padding: 4px 8px;
                margin: 2px 0;
                background-color: #f8f9fa;
                border-radius: 3px;
                font-family: monospace;
                font-size: 12px;
            ">
                <div>
                    <span style="font-weight: bold; color: {color};">[{step}]</span>
                    {icon} {message}
                </div>
                <div style="font-size: 10px; color: #888;">
                    {time_info}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        
        # 詳細情報があれば表示
        if details:
            with st.expander(f"📝 詳細 (ID: {log_id})", expanded=False):
                st.json(details)
    
    # ログ管理ボタン（一意のキーを設定）
    st.divider()
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🗑️ ログクリア", key="clear_logs_btn_panel", use_container_width=True):
            clear_debug_logs()
            st.rerun()
    with col2:
        if st.button("📋 コピー", key="copy_logs_btn_panel", use_container_width=True):
            log_text = "\n".join([
                f"[{log['timestamp']}] [{log['step']}] {log['message']} (経過: {log.get('elapsed_time', 0):.3f}秒)"
                for log in st.session_state.debug_logs
            ])
            st.code(log_text, language="text")
    
    st.caption(f"📊 ログ件数: {len(st.session_state.debug_logs)} 件")

# ==================== DDS送信関数 ====================
def send_detection_request(file_obj, source_type, dds_url, verify_ssl, data_type="DIM", content_block_id=None, mime_type=None):
    start_time = time.time()
    
    try:
        file_obj.seek(0)
        file_bytes = file_obj.read()
        b64_data = base64.b64encode(file_bytes).decode('utf-8')
        
        if source_type == "file":
            file_mime = get_mime_type(file_obj.name)
            if file_obj.type and file_obj.type != 'application/octet-stream':
                file_mime = file_obj.type
            
            block_id = file_obj.name.replace('.', '-') + "-001"
            
            request_data = {
                "context": [
                    {"name": "common.dataType", "value": ["DIM"]},
                    {"name": "common.application", "value": ["customAI"]},
                    {"name": "common.transactionId", "value": [st.session_state.txid]},
                    {"name": "common.filter", "value": [f["id"] for f in st.session_state.filters]},
                    {"name": "common.expectActionsAck", "value": ["true"]}
                ],
                "subject": {
                    "contentBlockId": "subject-001",
                    "mimeType": "text/plain",
                    "data": base64.b64encode(f"ファイル: {file_obj.name}".encode('utf-8')).decode('utf-8')
                },
                "attachments": [
                    {
                        "contentBlockId": block_id,
                        "mimeType": file_mime,
                        "data": b64_data,
                        "name": file_obj.name
                    }
                ]
            }
            
        else:
            block_id = content_block_id or "message-001"
            mime = mime_type or "text/plain"
            
            request_data = {
                "context": [
                    {"name": "common.dataType", "value": [data_type]},
                    {"name": "common.application", "value": ["customAI"]},
                    {"name": "common.transactionId", "value": [st.session_state.txid]},
                    {"name": "common.filter", "value": [f["id"] for f in st.session_state.filters]},
                    {"name": "common.expectActionsAck", "value": ["true"]}
                ],
                "subject": {
                    "contentBlockId": block_id,
                    "mimeType": "text/plain",
                    "data": b64_data
                }
            }
        
        json_data = json.dumps(request_data, ensure_ascii=False)
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        response = requests.post(
            dds_url,
            data=json_data,
            headers=headers,
            verify=not verify_ssl,
            timeout=60
        )
        
        elapsed = time.time() - start_time
        
        try:
            response_json = response.json()
            
            if response.status_code == 201:
                violations = response_json.get("violation", [])
                if violations is None:
                    violations = []
                request_id = response_json.get("requestId")
                return violations, request_id, response_json, None, elapsed
            else:
                error_info = {
                    "status_code": response.status_code,
                    "response_text": response.text,
                    "headers": dict(response.headers)
                }
                return [], None, None, error_info, elapsed
                
        except Exception as e:
            error_info = {
                "status_code": response.status_code,
                "response_text": response.text,
                "error": str(e)
            }
            return [], None, None, error_info, elapsed
            
    except requests.exceptions.ConnectionError as e:
        error_info = {
            "error_type": "ConnectionError",
            "message": str(e),
            "dds_url": dds_url
        }
        return [], None, None, error_info, time.time() - start_time
    except requests.exceptions.Timeout as e:
        error_info = {
            "error_type": "Timeout",
            "message": str(e)
        }
        return [], None, None, error_info, time.time() - start_time
    except Exception as e:
        error_info = {
            "error_type": "Exception",
            "message": str(e)
        }
        import traceback
        error_info["traceback"] = traceback.format_exc()
        return [], None, None, error_info, time.time() - start_time

# ==================== AI API呼び出し ====================
def normalize_api_url(url):
    url = url.strip()
    if url.endswith('/v1'):
        return url + '/chat/completions'
    if url.endswith('/v1/'):
        return url + 'chat/completions'
    if not url.endswith('/chat/completions') and not url.endswith('/completions'):
        if not url.endswith('/'):
            return url + '/v1/chat/completions'
        else:
            return url + 'v1/chat/completions'
    return url

def call_ai_api(messages, max_tokens=200):
    start_time = time.time()
    
    try:
        api_key = st.session_state.ai_api_key
        api_url = normalize_api_url(st.session_state.ai_api_url)
        model_name = st.session_state.ai_model
        
        if not api_url or not model_name:
            st.error("AI設定が不完全です。プロバイダーとモデルを選択してください。")
            return None, time.time() - start_time
        
        provider = st.session_state.selected_provider
        if provider in AI_PROVIDERS and AI_PROVIDERS[provider].get("api_key_required", True) and not api_key:
            st.error(f"{provider}はAPI Keyが必須です。API Keyを入力してください。")
            return None, time.time() - start_time
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": model_name,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.7,
            "stream": False
        }
        
        response = requests.post(api_url, headers=headers, json=data, timeout=60)
        
        elapsed = time.time() - start_time
        
        if response.status_code == 200:
            result = response.json()
            
            content = None
            reasoning = None
            
            if "choices" in result and len(result["choices"]) > 0:
                choice = result["choices"][0]
                message = choice.get("message", {})
                content = message.get("content", "")
                
                if "reasoning_content" in message:
                    reasoning = message.get("reasoning_content", "")
                
                if not content and reasoning:
                    return f"[推論: {reasoning}]", elapsed
                
                if not content and not reasoning:
                    st.warning("⚠️ AIからの応答が空です。")
                    return "（応答がありませんでした）", elapsed
                
                return content, elapsed
            
            elif "response" in result:
                return result["response"], elapsed
            
            else:
                st.error(f"予期しないレスポンス形式: {result}")
                return None, elapsed
                
        else:
            st.error(f"AI APIエラー: {response.status_code} - {response.text}")
            return None, elapsed
            
    except requests.exceptions.ConnectionError:
        st.error(f"❌ 接続エラー: APIサーバー ({api_url}) に接続できませんでした")
        return None, time.time() - start_time
    except requests.exceptions.Timeout:
        st.error("❌ タイムアウト: サーバーからの応答がありませんでした")
        return None, time.time() - start_time
    except Exception as e:
        st.error(f"AI API呼び出しエラー: {e}")
        return None, time.time() - start_time

# ==================== MessageWrapperクラス ====================
class MessageWrapper:
    def __init__(self, content, name):
        self.content = content
        self.name = name
        self.type = "text/plain"
        self.size = len(content)
    def read(self):
        return self.content.encode('utf-8')
    def seek(self, pos):
        pass

# ==================== サイドバー設定 ====================
with st.sidebar:
    st.header("⚙️ 設定")
    
    # DDS設定
    st.subheader("🔍 DDS設定")
    dds_host = st.text_input("DDSサーバーIP", value="192.168.2.132")
    dds_port = st.text_input("ポート", value="443")
    use_ssl = st.checkbox("SSL/TLSを使用", value=False)
    protocol = "https" if use_ssl else "http"
    dds_url = f"{protocol}://{dds_host}:{dds_port}/v2.0/DetectionRequests"
    st.session_state.dds_url = dds_url
    st.session_state.verify_ssl = use_ssl
    
    st.divider()
    
    # AI設定
    st.subheader("🤖 AI設定")
    
    provider_options = list(AI_PROVIDERS.keys())
    default_index = provider_options.index("ローカル (LM Studio)") if "ローカル (LM Studio)" in provider_options else 0
    
    selected_provider = st.selectbox(
        "AIプロバイダー",
        provider_options,
        index=default_index
    )
    st.session_state.selected_provider = selected_provider
    
    provider_config = AI_PROVIDERS[selected_provider]
    st.caption(f"📌 {provider_config.get('description', '')}")
    
    st.session_state.ai_api_url = provider_config["url"]
    st.info(f"📡 API URL: {provider_config['url']}")
    
    model_options = provider_config["models"].copy() if provider_config["models"] else []
    model_options.append("その他 (カスタム)")
    
    current_model = st.session_state.ai_model
    if current_model not in model_options:
        current_display = "その他 (カスタム)"
    else:
        current_display = current_model
    
    selected_model = st.selectbox(
        "モデル",
        model_options,
        index=model_options.index(current_display) if current_display in model_options else 0
    )
    
    if selected_model == "その他 (カスタム)":
        custom_model = st.text_input(
            "カスタムモデル名",
            value=st.session_state.ai_model if st.session_state.ai_model not in provider_config["models"] else "",
            placeholder="モデル名を自由に入力してください"
        )
        if custom_model:
            st.session_state.ai_model = custom_model
    else:
        st.session_state.ai_model = selected_model
    
    if provider_config.get("api_key_required", True):
        st.session_state.ai_api_key = st.text_input(
            "API Key",
            value=st.session_state.ai_api_key,
            type="password",
            placeholder="APIキーを入力してください"
        )
    else:
        default_key = provider_config.get("default_api_key", "")
        st.session_state.ai_api_key = default_key
        st.info(f"🔑 API Key: {default_key} (自動設定)")
    
    st.divider()
    
    # デバッグモード設定
    st.subheader("🐛 デバッグ設定")
    debug_mode = st.checkbox(
        "デバッグモードを有効にする",
        value=st.session_state.debug_mode,
        help="チェックを入れると、DDSリクエストとレスポンスの詳細が表示されます"
    )
    st.session_state.debug_mode = debug_mode
    
    if debug_mode:
        st.info("🔍 デバッグモード: ON")
    else:
        st.info("🔍 デバッグモード: OFF")
    
    # デバッグパネル表示切り替え
    if st.session_state.debug_logs:
        show_panel = st.checkbox(
            "📋 デバッグパネルを表示",
            value=st.session_state.get("show_debug_panel", True),
            help="チェックを入れると右側にデバッグログパネルが表示されます"
        )
        st.session_state.show_debug_panel = show_panel
    else:
        st.info("📋 デバッグログがありません")
    
    st.divider()
    
    # 接続テスト
    if st.button("🔗 AI接続テスト", use_container_width=True):
        if st.session_state.ai_api_url and st.session_state.ai_model:
            normalized_url = normalize_api_url(st.session_state.ai_api_url)
            st.info(f"📌 正規化されたURL: {normalized_url}")
            
            test_result, elapsed = call_ai_api([
                {"role": "user", "content": "Hello, this is a test. Please respond with 'OK'."}
            ], max_tokens=10)
            if test_result:
                st.success(f"✅ AI接続成功！ (モデル: {st.session_state.ai_model})")
                st.caption(f"⏱️ 応答時間: {elapsed:.2f}秒")
                st.session_state.ai_configured = True
            else:
                st.error("❌ AI接続失敗。設定を確認してください。")
        else:
            st.warning("⚠️ API URLとモデル名を確認してください")
    
    st.divider()
    
    # フィルター設定
    st.subheader("📋 検出フィルター")
    st.caption("最大10個")
    
    filters_to_remove = []
    for i, f in enumerate(st.session_state.filters):
        cols = st.columns([3, 1])
        with cols[0]:
            st.text_input(
                f"フィルター {i+1}",
                value=f["id"],
                key=f"filter_{i}",
                label_visibility="collapsed"
            )
            st.caption(f"📌 {f.get('name', '')}")
        with cols[1]:
            if st.button("🗑️", key=f"remove_filter_{i}", help="このフィルターを削除"):
                filters_to_remove.append(i)
    
    for idx in sorted(filters_to_remove, reverse=True):
        st.session_state.filters.pop(idx)
        st.rerun()
    
    if len(st.session_state.filters) < 10:
        with st.expander("➕ フィルターを追加"):
            new_filter_id = st.text_input("フィルターID (GUID)", key="new_filter_id")
            new_filter_name = st.text_input("フィルター名", key="new_filter_name")
            if st.button("追加", key="add_filter_btn", use_container_width=True):
                if new_filter_id:
                    st.session_state.filters.append({
                        "id": new_filter_id,
                        "name": new_filter_name or f"フィルター {len(st.session_state.filters)+1}"
                    })
                    st.rerun()
    
    st.divider()
    
    st.text_input("トランザクションID", value=st.session_state.txid, disabled=True)
    if st.button("🔄 新しいIDを生成", key="generate_txid_btn", use_container_width=True):
        st.session_state.txid = str(uuid.uuid4())
        st.rerun()
    
    st.divider()
    st.caption(f"📡 プロバイダー: **{st.session_state.get('selected_provider', '未設定')}**")
    st.caption(f"🤖 モデル: **{st.session_state.get('ai_model', '未設定')}**")

# ==================== メインコンテンツ + デバッグパネル ====================
show_debug = st.session_state.get("show_debug_panel", False) and len(st.session_state.debug_logs) > 0

if show_debug:
    main_col, debug_col = st.columns([2, 1])
else:
    main_col = st.container()
    debug_col = None

# ==================== メインコンテンツ ====================
with main_col:
    # ログ件数インジケーター
    if st.session_state.debug_logs:
        log_count = len(st.session_state.debug_logs)
        st.info(f"📋 デバッグログ: {log_count}件 (右パネルで表示)")
    
    # チャット履歴表示
    chat_container = st.container()
    with chat_container:
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.write(message["content"])
                if "violations" in message and message["violations"]:
                    st.error(f"🚫 ポリシー違反: {', '.join([v['name'] for v in message['violations']])}")

    # ==================== ファイルアップロードエリア ====================
    st.subheader("📎 ファイルアップロード")
    st.caption("ファイルを選択すると自動的にDDSで検査を実行します")

    uploaded_file = st.file_uploader(
        "ファイル選択",
        type=[".txt", ".csv", ".log", ".doc", ".docx", ".xls", ".xlsx", 
              ".ppt", ".pptx", ".pdf", ".eml", ".msg",
              ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".svg", ".ico",
              ".zip", ".7z", ".rar", ".tar", ".gz",
              ".html", ".htm", ".xml", ".json", ".css", ".js",
              ".rtf", ".odt", ".ods", ".odp"],
        key="file_uploader",
        label_visibility="collapsed"
    )

    if uploaded_file:
        if st.session_state.filename != uploaded_file.name:
            st.session_state.file_checked = False
            st.session_state.file_violations = []
            st.session_state.file_approved = False
            st.session_state.filename = uploaded_file.name
            uploaded_file.seek(0)
            st.session_state.file_data = uploaded_file.read()
            st.session_state.file_checked = False
        
        file_mime = get_mime_type(uploaded_file.name)
        if uploaded_file.type and uploaded_file.type != 'application/octet-stream':
            file_mime = uploaded_file.type
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.info(f"📎 ファイル: {st.session_state.filename}")
        with col2:
            st.info(f"📊 サイズ: {len(st.session_state.file_data)/1024:.1f} KB")
        with col3:
            st.info(f"📝 MIME: {file_mime}")
        with col4:
            ext = st.session_state.filename.split('.')[-1].upper() if '.' in st.session_state.filename else "不明"
            st.info(f"📄 形式: {ext}")
        
        # 画像ファイルのプレビュー
        if file_mime and file_mime.startswith('image/'):
            try:
                image = Image.open(io.BytesIO(st.session_state.file_data))
                st.image(image, caption=f"画像プレビュー: {st.session_state.filename}", width=300)
            except Exception as e:
                st.warning(f"画像のプレビュー表示に失敗しました: {e}")
        
        # テキストファイルのプレビュー
        elif file_mime and "text" in file_mime:
            try:
                content = st.session_state.file_data.decode('utf-8', errors='ignore')
                st.text_area("📄 ファイル内容プレビュー", content[:1000], height=150)
                if len(content) > 1000:
                    st.caption(f"... 他 {len(content) - 1000} 文字")
            except:
                pass
        
        if not st.session_state.file_checked:
            with st.spinner(f"🔍 DDSでファイルを検査中... (ファイル: {st.session_state.filename})"):
                progress_bar = st.progress(0)
                for i in range(100):
                    time.sleep(0.02)
                    progress_bar.progress(i + 1)
                progress_bar.empty()
                
                class FileWrapper:
                    def __init__(self, name, data):
                        self.name = name
                        self.data = data
                        self.type = get_mime_type(name)
                    def read(self):
                        return self.data
                    def seek(self, pos):
                        pass
                
                file_wrapper = FileWrapper(st.session_state.filename, st.session_state.file_data)
                violations, request_id, response_data, error_info, elapsed = send_detection_request(
                    file_wrapper, 
                    "file", 
                    st.session_state.dds_url, 
                    st.session_state.verify_ssl,
                    data_type="DIM"
                )
                
                st.session_state.file_violations = violations
                st.session_state.file_checked = True
                
                if st.session_state.debug_mode:
                    if violations and len(violations) > 0:
                        policy_names = [v["name"] for v in violations]
                        add_debug_log("ファイル検査", f"ポリシー違反: {', '.join(policy_names)}", "warning", elapsed, response_data)
                    else:
                        add_debug_log("ファイル検査", "ポリシー違反はありません", "success", elapsed, response_data)
                
                if error_info:
                    if not st.session_state.debug_mode:
                        st.error(f"❌ DDSエラー: ステータスコード {error_info.get('status_code', '不明')}")
                    else:
                        st.error(f"❌ DDSエラー: {error_info}")
                elif violations and len(violations) > 0:
                    st.session_state.file_approved = False
                    policy_names = [v["name"] for v in violations]
                    st.error(f"🚫 ポリシー違反: {', '.join(policy_names)}")
                    st.warning("⚠️ このファイルはポリシーに違反しているため、AIに送信できません")
                else:
                    st.session_state.file_approved = True
                    st.success(f"✅ ファイル検査完了: ポリシー違反はありません (⏱️ {elapsed:.2f}秒)")
                    if request_id and st.session_state.debug_mode:
                        st.info(f"📌 Request ID: {request_id}")
                    st.info("💬 メッセージを入力して送信すると、このファイルが添付されてAIに送信されます")
        
        else:
            if st.session_state.file_violations and len(st.session_state.file_violations) > 0:
                policy_names = [v["name"] for v in st.session_state.file_violations]
                st.error(f"🚫 ポリシー違反: {', '.join(policy_names)}")
                st.warning("⚠️ このファイルはポリシーに違反しているため、AIに送信できません")
            else:
                st.success("✅ ファイルは検査済み: ポリシー違反はありません")
                st.info("💬 メッセージを入力して送信すると、このファイルが添付されてAIに送信されます")

    # ==================== メッセージ入力エリア ====================
    st.divider()

    if uploaded_file and st.session_state.file_approved and not st.session_state.file_violations:
        placeholder_text = "ファイルがアップロードされています。何を聞きたいですか？"
    elif uploaded_file and st.session_state.file_violations:
        placeholder_text = "ファイルがポリシー違反のため、メッセージのみ送信できます"
    else:
        placeholder_text = "メッセージを入力してください..."

    user_input = st.chat_input(placeholder_text)

    # ==================== メッセージ処理 ====================
    if user_input:
        st.session_state.process_start_time = time.time()
        
        with st.chat_message("user"):
            st.write(user_input)
            if uploaded_file and st.session_state.file_approved and not st.session_state.file_violations:
                st.write(f"📎 {st.session_state.filename} (添付済み)")
        
        # ===== ステップ1: DDSチェック（メッセージ） =====
        step1_start = time.time()
        add_debug_log("ステップ1", "DDSでメッセージを検査中...", "info")
        
        status_message = st.info("🔍 [ステップ1] DDSでメッセージを検査中...")
        
        message_wrapper = MessageWrapper(user_input, "message")
        violations, request_id, response_data, error_info, elapsed = send_detection_request(
            message_wrapper, 
            "message", 
            st.session_state.dds_url, 
            st.session_state.verify_ssl,
            data_type="DIM",
            content_block_id="message-001"
        )
        
        if violations is None:
            violations = []
        
        status_message.empty()
        st.info(f"✅ [ステップ1] DDSメッセージ検査完了 (⏱️ {elapsed:.2f}秒)")
        add_debug_log("ステップ1", f"DDSメッセージ検査完了", "success", elapsed, response_data)
        
        if error_info:
            st.error(f"❌ DDSエラー: ステータスコード {error_info.get('status_code', '不明')}")
            add_debug_log("ステップ1", f"エラー: {error_info}", "error", elapsed)
            st.stop()
        
        if response_data and not st.session_state.debug_mode:
            if response_data.get("violation") and len(response_data.get("violation", [])) > 0:
                st.warning(f"⚠️ {len(response_data.get('violation', []))}件の違反が検出されました")
        
        if violations and len(violations) > 0:
            policy_names = [v["name"] for v in violations]
            st.error(f"🚫 ポリシー違反が検出されました: {', '.join(policy_names)}")
            add_debug_log("ステップ1", f"ポリシー違反: {', '.join(policy_names)}", "warning", elapsed)
            
            error_msg = f"🚫 以下のポリシーに違反しています: {', '.join(policy_names)}"
            st.session_state.messages.append({
                "role": "assistant",
                "content": error_msg,
                "violations": violations
            })
            
            with st.chat_message("assistant"):
                st.error(error_msg)
            
            st.rerun()
            st.stop()
        else:
            st.success("✅ [ステップ1] ポリシー違反はありませんでした")
            add_debug_log("ステップ1", "ポリシー違反はありませんでした", "success", elapsed)
        
        # ===== ステップ2: AI送信 =====
        add_debug_log("ステップ2", "AIにリクエストを送信中...", "info")
        st.info("🤖 [ステップ2] AIにリクエストを送信中...")
        
        file_to_send = None
        filename_to_send = None
        
        if uploaded_file and st.session_state.file_approved and not st.session_state.file_violations:
            file_to_send = st.session_state.file_data
            filename_to_send = st.session_state.filename
        
        start_time = time.time()
        status_placeholder = st.empty()
        status_placeholder.info(f"⏳ AI応答を待っています... (0秒経過)")
        
        with st.spinner(f"🤖 {st.session_state.ai_model} に送信中..."):
            def update_status():
                elapsed = 0
                while True:
                    time.sleep(1)
                    elapsed += 1
                    status_placeholder.info(f"⏳ AI応答を待っています... ({elapsed}秒経過)")
                    if elapsed > 10:
                        status_placeholder.info(f"⏳ AI応答を待っています... ({elapsed}秒経過) 少々お待ちください")
                    if elapsed > 30:
                        status_placeholder.warning(f"⏳ AI応答を待っています... ({elapsed}秒経過) 応答に時間がかかっています")
            
            status_thread = threading.Thread(target=update_status, daemon=True)
            status_thread.start()
            
            ai_messages = []
            for msg in st.session_state.messages:
                if msg["role"] != "assistant" or "violations" not in msg:
                    ai_messages.append({"role": msg["role"], "content": msg["content"]})
            
            current_msg = user_input
            if file_to_send and filename_to_send:
                current_msg += f"\n[添付ファイル: {filename_to_send}, サイズ: {len(file_to_send)}バイト]"
            
            ai_messages.append({"role": "user", "content": current_msg})
            
            ai_response, ai_elapsed = call_ai_api(ai_messages, max_tokens=200)
            
            status_placeholder.empty()
            elapsed_time = time.time() - start_time
            
            if ai_response:
                st.success(f"✅ [ステップ2] AIからレスポンスを受信しました (⏱️ {ai_elapsed:.2f}秒)")
                add_debug_log("ステップ2", f"AIからレスポンスを受信", "success", ai_elapsed)
                
                # ===== ステップ4: AI応答をDDSで再チェック =====
                step4_start = time.time()
                add_debug_log("ステップ4", "AIレスポンスをDDSに送信してDLP走査を実行中...", "info")
                st.info("🔍 [ステップ4] AIレスポンスをDDSに送信してDLP走査を実行中...")
                
                ai_message_wrapper = MessageWrapper(ai_response, "ai_response")
                v, request_id2, response_data2, error_info2, elapsed2 = send_detection_request(
                    ai_message_wrapper,
                    "message",
                    st.session_state.dds_url,
                    st.session_state.verify_ssl,
                    data_type="DIM",
                    content_block_id="ai-response-001"
                )
                
                if v is None:
                    v = []
                
                step4_elapsed = time.time() - step4_start
                st.info(f"✅ [ステップ4] DLP走査が完了しました (⏱️ {elapsed2:.2f}秒)")
                add_debug_log("ステップ4", f"DLP走査完了", "success", elapsed2, response_data2)
                
                if error_info2:
                    st.error(f"❌ DDSエラー: ステータスコード {error_info2.get('status_code', '不明')}")
                    add_debug_log("ステップ4", f"エラー: {error_info2}", "error", elapsed2)
                    st.stop()
                
                # ===== ステップ5: AI応答の違反チェック結果 =====
                if v and len(v) > 0:
                    policy_names = [v["name"] for v in v]
                    st.error(f"🚫 [ステップ5] AIレスポンスにポリシー違反が検出されました: {', '.join(policy_names)}")
                    add_debug_log("ステップ5", f"ポリシー違反: {', '.join(policy_names)}", "warning", elapsed2)
                    
                    error_msg = f"🚫 AIの回答にDLP違反した内容がありました。表示できません。\n違反ポリシー: {', '.join(policy_names)}"
                    
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": error_msg,
                        "violations": v
                    })
                    
                    with st.chat_message("assistant"):
                        st.error(error_msg)
                else:
                    st.success("✅ [ステップ5] AIレスポンスにポリシー違反はありませんでした")
                    add_debug_log("ステップ5", "ポリシー違反はありませんでした", "success", elapsed2)
                    
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": ai_response,
                        "violations": []
                    })
                    
                    with st.chat_message("assistant"):
                        st.write(ai_response)
                        st.caption(f"⏱️ 応答時間: {elapsed_time:.2f}秒")
            else:
                st.error(f"❌ [ステップ2] {st.session_state.ai_model} APIからの応答がありませんでした")
                add_debug_log("ステップ2", f"{st.session_state.ai_model} APIからの応答なし", "error", ai_elapsed if 'ai_elapsed' in locals() else 0)
                error_msg = f"❌ {st.session_state.ai_model} APIからの応答がありませんでした"
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": error_msg,
                    "violations": []
                })
                with st.chat_message("assistant"):
                    st.error(error_msg)
        
        st.rerun()

# ==================== デバッグパネル（右側） ====================
if show_debug and debug_col is not None:
    with debug_col:
        st.subheader("📋 デバッグログ")
        st.caption(f"🕐 最終更新: {datetime.now().strftime('%H:%M:%S')}")
        st.divider()
        
        # ログクリアボタン（上部、一意のキー）
        if st.button("🗑️ ログクリア", key="clear_logs_top_btn", use_container_width=True):
            clear_debug_logs()
            st.rerun()
        
        st.divider()
        
        # スクロール可能なログ表示
        with st.container(height=550):
            render_debug_logs()
