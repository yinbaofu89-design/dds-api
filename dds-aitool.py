import streamlit as st
import base64
import json
import uuid
import requests
import os
import mimetypes
from datetime import datetime

# ページ設定
st.set_page_config(
    page_title="DDS + DeepSeek 統合ツール",
    page_icon="🔒",
    layout="wide"
)

st.title("🔒 DDS + DeepSeek 統合コンテンツ検査ツール")
st.caption("DDSでポリシー違反をチェック後、DeepSeek APIで応答を生成")

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
if "deepseek_configured" not in st.session_state:
    st.session_state.deepseek_configured = False

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

# ==================== DeepSeek API呼び出し ====================
def call_deepseek(messages, max_tokens=200):
    """DeepSeek APIを呼び出し"""
    try:
        api_key = st.session_state.deepseek_api_key
        api_url = st.session_state.deepseek_api_url
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "deepseek-chat",
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.7
        }
        
        response = requests.post(api_url, headers=headers, json=data, timeout=60)
        
        if response.status_code == 200:
            result = response.json()
            return result["choices"][0]["message"]["content"]
        else:
            st.error(f"DeepSeek APIエラー: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        st.error(f"DeepSeek呼び出しエラー: {e}")
        return None

# ==================== サイドバー設定 ====================
with st.sidebar:
    st.header("⚙️ 設定")
    
    # DDS設定
    st.subheader("🔍 DDS設定")
    dds_host = st.text_input("DDSサーバーIP", value="192.168.2.132")
    dds_port = st.text_input("ポート", value="443")
    use_ssl = st.checkbox("SSL/TLSを使用", value=True)
    protocol = "https" if use_ssl else "http"
    st.session_state.dds_url = f"{protocol}://{dds_host}:{dds_port}/v2.0/DetectionRequests"
    st.session_state.verify_ssl = use_ssl
    
    st.divider()
    
    # DeepSeek設定
    st.subheader("🤖 DeepSeek設定")
    st.session_state.deepseek_api_url = st.text_input(
        "DeepSeek API URL",
        value="https://api.deepseek.com/v1/chat/completions"
    )
    st.session_state.deepseek_api_key = st.text_input(
        "API Key",
        type="password",
        placeholder="sk-... を入力"
    )
    
    if st.button("🔗 DeepSeek接続テスト", use_container_width=True):
        if st.session_state.deepseek_api_key:
            test_result = call_deepseek([
                {"role": "user", "content": "Hello, this is a test. Please respond with 'OK'."}
            ], max_tokens=10)
            if test_result:
                st.success("✅ DeepSeek接続成功！")
                st.session_state.deepseek_configured = True
            else:
                st.error("❌ DeepSeek接続失敗。APIキーとURLを確認してください。")
        else:
            st.warning("⚠️ API Keyを入力してください")
    
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
    
    # トランザクションID
    st.text_input("トランザクションID", value=st.session_state.txid, disabled=True)
    if st.button("🔄 新しいIDを生成", use_container_width=True):
        st.session_state.txid = str(uuid.uuid4())
        st.rerun()

# ==================== メイン画面 ====================
# チャット履歴表示
chat_container = st.container()
with chat_container:
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])
            if "violations" in message and message["violations"]:
                st.error(f"🚫 ポリシー違反: {', '.join([v['name'] for v in message['violations']])}")

# 入力エリア
input_col1, input_col2 = st.columns([3, 1])

with input_col1:
    user_input = st.chat_input("メッセージを入力してください...")

with input_col2:
    uploaded_file = st.file_uploader(
        "📎 ファイル添付",
        type=[".txt", ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".csv", ".json", ".xml", ".zip"],
        key="file_uploader"
    )

# アップロードファイル情報表示
if uploaded_file:
    st.info(f"📎 添付ファイル: {uploaded_file.name} ({uploaded_file.size/1024:.1f} KB)")

# ==================== メッセージ処理 ====================
if user_input or uploaded_file:
    # 送信内容の準備
    message_content = user_input or ""
    file_data = None
    filename = None
    
    if uploaded_file:
        file_data = uploaded_file.read()
        filename = uploaded_file.name
        if not message_content:
            message_content = f"ファイル: {filename}"
    
    # ユーザーメッセージを表示
    with st.chat_message("user"):
        if user_input:
            st.write(user_input)
        if uploaded_file:
            st.write(f"📎 {filename}")
    
    # ===== DDSチェック =====
    with st.spinner("🔍 DDSでポリシーチェック中..."):
        violations = []
        
        # テキストメッセージをチェック
        if user_input:
            v, _ = check_dds(user_input, "text")
            violations.extend(v)
        
        # ファイルをチェック
        if uploaded_file and file_data:
            v, _ = check_dds("", "file", filename, file_data)
            violations.extend(v)
    
    # ===== DDS結果処理 =====
    if violations:
        # ポリシー違反あり
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
        # ポリシー違反なし → DeepSeekに送信
        with st.spinner("🤖 DeepSeekに送信中..."):
            # DeepSeek用メッセージ作成
            deepseek_messages = []
            
            # 過去の履歴を追加（違反メッセージは除く）
            for msg in st.session_state.messages:
                if msg["role"] != "assistant" or "violations" not in msg:
                    deepseek_messages.append({"role": msg["role"], "content": msg["content"]})
            
            # 現在のメッセージを追加
            current_msg = user_input or f"ファイル: {filename}"
            if uploaded_file:
                current_msg += f"\n[添付ファイル: {filename}, サイズ: {len(file_data)}バイト]"
            deepseek_messages.append({"role": "user", "content": current_msg})
            
            # DeepSeek呼び出し
            deepseek_response = call_deepseek(deepseek_messages, max_tokens=200)
            
            if deepseek_response:
                # DeepSeekの応答をDDSでチェック
                with st.spinner("🔍 DeepSeek応答をDDSで再チェック中..."):
                    v, _ = check_dds(deepseek_response, "text")
                
                if v:
                    # DeepSeek応答がポリシー違反
                    policy_names = [v["name"] for v in v]
                    error_msg = f"🚫 DeepSeekの応答が以下のポリシーに違反しています: {', '.join(policy_names)}"
                    
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": error_msg,
                        "violations": v
                    })
                    
                    with st.chat_message("assistant"):
                        st.error(error_msg)
                else:
                    # 正常応答
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": deepseek_response,
                        "violations": []
                    })
                    
                    with st.chat_message("assistant"):
                        st.write(deepseek_response)
            else:
                # DeepSeekエラー
                error_msg = "❌ DeepSeek APIからの応答がありませんでした"
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": error_msg,
                    "violations": []
                })
                with st.chat_message("assistant"):
                    st.error(error_msg)
    
    # ページ更新
    st.rerun()

# ==================== フッター ====================
st.divider()
st.caption("🔒 DDS + DeepSeek 統合コンテンツ検査ツール v2.0")
st.caption("📖 DDS API: [Broadcom Documentation](https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/25-1/about-application-detection/overview-of-the-detection-rest-api-2-0.html)")