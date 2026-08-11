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
    st.session_state.ai_api_key = "ollama"
if "ai_api_url" not in st.session_state:
    st.session_state.ai_api_url = "http://localhost:11434/v1/chat/completions"
if "ai_model" not in st.session_state:
    st.session_state.ai_model = "llama3"
if "selected_provider" not in st.session_state:
    st.session_state.selected_provider = "ローカル (Ollama)"

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
        '.doc': 'application/msword',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.xls': 'application/vnd.ms-excel',
        '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        '.ppt': 'application/vnd.ms-powerpoint',
        '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        '.pdf': 'application/pdf',
        '.eml': 'message/rfc822', '.msg': 'application/vnd.ms-outlook',
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
        '.gif': 'image/gif', '.bmp': 'image/bmp',
        '.zip': 'application/zip', '.7z': 'application/x-7z-compressed',
        '.rar': 'application/vnd.rar',
        '.html': 'text/html', '.htm': 'text/html',
        '.xml': 'text/xml', '.json': 'application/json',
        '.rtf': 'application/rtf',
        '.odt': 'application/vnd.oasis.opendocument.text',
        '.ods': 'application/vnd.oasis.opendocument.spreadsheet',
    }
    return mime_map.get(ext, 'application/octet-stream')

# ==================== DDS検出関数 ====================
def check_dds(content, content_type="text", filename=None, file_data=None):
    """
    DDSでコンテンツを検査
    戻り値: (violations, request_id)
    violations: 違反ポリシーのリスト [{"policyId": "xxx", "name": "xxx"}, ...]
    """
    try:
        # DDS設定を取得
        dds_url = st.session_state.dds_url
        verify_ssl = st.session_state.verify_ssl
        
        # リクエストデータ作成
        if content_type == "text":
            # テキストメッセージ
            b64_data = base64.b64encode(content.encode('utf-8')).decode('utf-8')
            request_data = {
                "context": [
                    {"name": "common.dataType", "value": ["MSG"]},
                    {"name": "common.application", "value": ["securlet.box"]},
                    {"name": "common.transactionId", "value": [st.session_state.txid]},
                    {"name": "common.filter", "value": [f["id"] for f in st.session_state.filters]},
                    {"name": "common.expectActionsAck", "value": ["true"]}
                ],
                "subject": {
                    "contentBlockId": f"msg-{uuid.uuid4().hex[:8]}",
                    "mimeType": "text/plain",
                    "data": b64_data
                }
            }
        else:
            # ファイル添付
            b64_data = base64.b64encode(file_data).decode('utf-8')
            file_mime = get_mime_type(filename)
            
            request_data = {
                "context": [
                    {"name": "common.dataType", "value": ["DIM"]},
                    {"name": "common.application", "value": ["securlet.box"]},
                    {"name": "common.transactionId", "value": [st.session_state.txid]},
                    {"name": "common.filter", "value": [f["id"] for f in st.session_state.filters]},
                    {"name": "common.expectActionsAck", "value": ["true"]}
                ],
                "subject": {
                    "contentBlockId": f"subject-{uuid.uuid4().hex[:8]}",
                    "mimeType": "text/plain",
                    "data": base64.b64encode(f"ファイル: {filename}".encode('utf-8')).decode('utf-8')
                },
                "attachments": [
                    {
                        "contentBlockId": f"file-{uuid.uuid4().hex[:8]}",
                        "mimeType": file_mime,
                        "data": b64_data,
                        "name": filename
                    }
                ]
            }
        
        # DDS送信
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        response = requests.post(
            dds_url,
            data=json.dumps(request_data),
            headers=headers,
            verify=not verify_ssl,
            timeout=30
        )
        
        if response.status_code == 201:
            result = response.json()
            violations = result.get("violation", [])
            request_id = result.get("requestId")
            return violations, request_id
        else:
            return [], None
            
    except Exception as e:
        st.error(f"DDSチェックエラー: {e}")
        return [], None

# ==================== AI API呼び出し（汎用） ====================
def normalize_api_url(url):
    """API URLを正規化する"""
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
    """
    汎用AI APIを呼び出し
    設定されたAPI URL、API Key、モデル名を使用
    """
    try:
        api_key = st.session_state.ai_api_key
        api_url = normalize_api_url(st.session_state.ai_api_url)
        model_name = st.session_state.ai_model
        
        if not api_url or not model_name:
            st.error("AI設定が不完全です。プロバイダーとモデルを選択してください。")
            return None
        
        # APIキーが必須だが空の場合
        provider = st.session_state.selected_provider
        if provider in AI_PROVIDERS and AI_PROVIDERS[provider].get("api_key_required", True) and not api_key:
            st.error(f"{provider}はAPI Keyが必須です。API Keyを入力してください。")
            return None
        
        # デバッグ情報
        if st.session_state.get("debug_mode", False):
            st.write(f"**API URL:** {api_url}")
            st.write(f"**モデル:** {model_name}")
            st.write(f"**プロバイダー:** {provider}")
        
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
        
        if response.status_code == 200:
            result = response.json()
            
            # デバッグ用にレスポンス全体を表示
            if st.session_state.get("debug_mode", False):
                st.write("**APIレスポンス:**")
                st.json(result)
            
            # 様々なレスポンス形式に対応
            content = None
            reasoning = None
            
            # OpenAI互換形式
            if "choices" in result and len(result["choices"]) > 0:
                choice = result["choices"][0]
                message = choice.get("message", {})
                
                # contentを取得
                content = message.get("content", "")
                
                # reasoning_content（Qwenなど）を取得
                if "reasoning_content" in message:
                    reasoning = message.get("reasoning_content", "")
                
                # もしcontentが空でreasoningがある場合、reasoningを表示
                if not content and reasoning:
                    return f"[推論: {reasoning}]"
                
                # 両方とも空の場合
                if not content and not reasoning:
                    st.warning("⚠️ AIからの応答が空です。モデルが正しく応答していない可能性があります。")
                    st.info("💡 デバッグモードを有効にしてレスポンスを確認してください。")
                    return "（応答がありませんでした）"
                
                return content
            
            # その他の形式（Ollamaの非互換形式など）
            elif "response" in result:
                return result["response"]
            
            else:
                st.error(f"予期しないレスポンス形式: {result}")
                st.info("💡 デバッグモードを有効にしてレスポンスの構造を確認してください。")
                return None
                
        else:
            st.error(f"AI APIエラー: {response.status_code} - {response.text}")
            return None
            
    except requests.exceptions.ConnectionError:
        st.error(f"❌ 接続エラー: APIサーバー ({api_url}) に接続できませんでした")
        st.info("💡 サーバーが起動しているか、URLが正しいか確認してください。")
        return None
    except requests.exceptions.Timeout:
        st.error("❌ タイムアウト: サーバーからの応答がありませんでした")
        return None
    except Exception as e:
        st.error(f"AI API呼び出しエラー: {e}")
        import traceback
        if st.session_state.get("debug_mode", False):
            st.code(traceback.format_exc())
        return None

# ==================== サイドバー設定 ====================
with st.sidebar:
    st.header("⚙️ 設定")
    
    # DDS設定
    st.subheader("🔍 DDS設定")
    dds_host = st.text_input("DDSサーバーIP", value="192.168.2.132")
    dds_port = st.text_input("ポート", value="443")
    use_ssl = st.checkbox("SSL/TLSを使用", value=False)
    protocol = "https" if use_ssl else "http"
    st.session_state.dds_url = f"{protocol}://{dds_host}:{dds_port}/v2.0/DetectionRequests"
    st.session_state.verify_ssl = use_ssl
    
    st.divider()
    
    # AI設定（統合）
    st.subheader("🤖 AI設定")
    
    # プロバイダー選択（デフォルト: ローカル (Ollama)）
    provider_options = list(AI_PROVIDERS.keys())
    default_index = provider_options.index("ローカル (Ollama)") if "ローカル (Ollama)" in provider_options else 0
    
    selected_provider = st.selectbox(
        "AIプロバイダー",
        provider_options,
        index=default_index,
        help="使用するAIプロバイダーを選択してください"
    )
    st.session_state.selected_provider = selected_provider
    
    provider_config = AI_PROVIDERS[selected_provider]
    
    # プロバイダー説明
    st.caption(f"📌 {provider_config.get('description', '')}")
    
    # URLを自動設定
    st.session_state.ai_api_url = provider_config["url"]
    st.info(f"📡 API URL: {provider_config['url']}")
    
    # モデル選択（プルダウン + 「その他」オプション）
    model_options = provider_config["models"].copy() if provider_config["models"] else []
    model_options.append("その他 (カスタム)")
    
    # 現在のモデルがリストにあるかチェック
    current_model = st.session_state.ai_model
    if current_model not in model_options:
        current_display = "その他 (カスタム)"
    else:
        current_display = current_model
    
    # モデル選択
    selected_model = st.selectbox(
        "モデル",
        model_options,
        index=model_options.index(current_display) if current_display in model_options else 0,
        help="使用するモデルを選択してください。『その他』を選ぶと自由に入力できます"
    )
    
    # モデル処理
    if selected_model == "その他 (カスタム)":
        custom_model = st.text_input(
            "カスタムモデル名",
            value=st.session_state.ai_model if st.session_state.ai_model not in provider_config["models"] else "",
            placeholder="モデル名を自由に入力してください",
            help="任意のモデル名を入力できます"
        )
        if custom_model:
            st.session_state.ai_model = custom_model
    else:
        st.session_state.ai_model = selected_model
    
    # API Key設定
    if provider_config.get("api_key_required", True):
        st.session_state.ai_api_key = st.text_input(
            "API Key",
            value=st.session_state.ai_api_key,
            type="password",
            placeholder="APIキーを入力してください",
            help="APIアクセス用の認証キー"
        )
    else:
        default_key = provider_config.get("default_api_key", "")
        st.session_state.ai_api_key = default_key
        st.info(f"🔑 API Key: {default_key} (自動設定)")
    
    # デバッグモード
    debug_mode = st.checkbox("🐛 デバッグモード", value=False, help="APIリクエストとレスポンスの詳細を表示")
    st.session_state.debug_mode = debug_mode
    
    # 接続テストボタン
    if st.button("🔗 AI接続テスト", use_container_width=True):
        if st.session_state.ai_api_url and st.session_state.ai_model:
            normalized_url = normalize_api_url(st.session_state.ai_api_url)
            st.info(f"📌 正規化されたURL: {normalized_url}")
            
            test_result = call_ai_api([
                {"role": "user", "content": "Hello, this is a test. Please respond with 'OK'."}
            ], max_tokens=10)
            if test_result:
                st.success(f"✅ AI接続成功！ (プロバイダー: {selected_provider}, モデル: {st.session_state.ai_model})")
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
            if st.button("🗑️", key=f"remove_{i}"):
                filters_to_remove.append(i)
    
    for idx in sorted(filters_to_remove, reverse=True):
        st.session_state.filters.pop(idx)
        st.rerun()
    
    if len(st.session_state.filters) < 10:
        with st.expander("➕ フィルターを追加"):
            new_filter_id = st.text_input("フィルターID (GUID)", key="new_filter_id")
            new_filter_name = st.text_input("フィルター名", key="new_filter_name")
            if st.button("追加", use_container_width=True):
                if new_filter_id:
                    st.session_state.filters.append({
                        "id": new_filter_id,
                        "name": new_filter_name or f"フィルター {len(st.session_state.filters)+1}"
                    })
                    st.rerun()
    
    st.divider()
    
    st.text_input("トランザクションID", value=st.session_state.txid, disabled=True)
    if st.button("🔄 新しいIDを生成", use_container_width=True):
        st.session_state.txid = str(uuid.uuid4())
        st.rerun()
    
    st.divider()
    st.caption(f"📡 プロバイダー: **{st.session_state.get('selected_provider', '未設定')}**")
    st.caption(f"🤖 モデル: **{st.session_state.get('ai_model', '未設定')}**")

# ==================== メイン画面 ====================
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
    type=[".txt", ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".csv", ".json", ".xml", ".zip"],
    key="file_uploader",
    label_visibility="collapsed"
)

# ファイルがアップロードされた場合の処理
if uploaded_file:
    if st.session_state.filename != uploaded_file.name:
        st.session_state.file_checked = False
        st.session_state.file_violations = []
        st.session_state.file_approved = False
        st.session_state.filename = uploaded_file.name
        st.session_state.file_data = uploaded_file.read()
        st.session_state.file_checked = False
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.info(f"📎 ファイル: {st.session_state.filename}")
    with col2:
        st.info(f"📊 サイズ: {len(st.session_state.file_data)/1024:.1f} KB")
    with col3:
        st.info(f"📝 MIME: {get_mime_type(st.session_state.filename)}")
    
    if not st.session_state.file_checked:
        with st.spinner(f"🔍 DDSでファイルを検査中... (ファイル: {st.session_state.filename})"):
            progress_bar = st.progress(0)
            for i in range(100):
                time.sleep(0.02)
                progress_bar.progress(i + 1)
            progress_bar.empty()
            
            violations, request_id = check_dds(
                "", 
                "file", 
                st.session_state.filename, 
                st.session_state.file_data
            )
            
            st.session_state.file_violations = violations
            st.session_state.file_checked = True
            
            if violations:
                st.session_state.file_approved = False
                policy_names = [v["name"] for v in violations]
                st.error(f"🚫 ポリシー違反: {', '.join(policy_names)}")
                st.warning("⚠️ このファイルはポリシーに違反しているため、AIに送信できません")
            else:
                st.session_state.file_approved = True
                st.success(f"✅ ファイル検査完了: ポリシー違反はありません (Request ID: {request_id})")
                st.info("💬 メッセージを入力して送信すると、このファイルが添付されてAIに送信されます")
    
    else:
        if st.session_state.file_violations:
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
    with st.chat_message("user"):
        st.write(user_input)
        if uploaded_file and st.session_state.file_approved and not st.session_state.file_violations:
            st.write(f"📎 {st.session_state.filename} (添付済み)")
    
    with st.spinner("🔍 DDSでメッセージをチェック中..."):
        violations = []
        if user_input:
            v, _ = check_dds(user_input, "text")
            violations.extend(v)
    
    if violations:
        policy_names = [v["name"] for v in violations]
        error_msg = f"🚫 以下のポリシーに違反しています: {', '.join(policy_names)}"
        
        st.session_state.messages.append({
            "role": "assistant",
            "content": error_msg,
            "violations": violations
        })
        
        with st.chat_message("assistant"):
            st.error(error_msg)
        
    else:
        file_to_send = None
        filename_to_send = None
        
        if uploaded_file and st.session_state.file_approved and not st.session_state.file_violations:
            file_to_send = st.session_state.file_data
            filename_to_send = st.session_state.filename
        
        start_time = time.time()
        status_placeholder = st.empty()
        
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
            
            ai_response = call_ai_api(ai_messages, max_tokens=200)
            
            status_placeholder.empty()
            elapsed_time = time.time() - start_time
            
            if ai_response:
                with st.spinner("🔍 AI応答をDDSで再チェック中..."):
                    v, _ = check_dds(ai_response, "text")
                
                if v:
                    policy_names = [v["name"] for v in v]
                    error_msg = f"🚫 AIの応答が以下のポリシーに違反しています: {', '.join(policy_names)}"
                    
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": error_msg,
                        "violations": v
                    })
                    
                    with st.chat_message("assistant"):
                        st.error(error_msg)
                else:
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": ai_response,
                        "violations": []
                    })
                    
                    with st.chat_message("assistant"):
                        st.write(ai_response)
                        st.caption(f"⏱️ 応答時間: {elapsed_time:.1f}秒")
            else:
                error_msg = f"❌ {st.session_state.ai_model} APIからの応答がありませんでした"
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": error_msg,
                    "violations": []
                })
                with st.chat_message("assistant"):
                    st.error(error_msg)
    
    st.rerun()

# ==================== フッター ====================
st.divider()
st.caption("🔒 DDS + AI 統合コンテンツ検査ツール v2.0")
st.caption("📖 DDS API: [Broadcom Documentation](https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/25-1/about-application-detection/overview-of-the-detection-rest-api-2-0.html)")
