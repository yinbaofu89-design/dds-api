# ===== ステップ3: AI応答をDDSで再チェック =====
status_message2 = st.info("🔍 AIの回答をDDSで検査中...")

# AIの応答をDDSでチェック
v, request_id2, response_data2 = check_dds(ai_response, "text")
if v is None:
    v = []

if request_id2:
    status_message2.empty()
    st.info(f"✅ AI応答のDDS検査完了 (Request ID: {request_id2})")
    
    # DDSレスポンス詳細を表示
    if response_data2:
        with st.expander("📋 AI応答のDDSレスポンス詳細"):
            st.json(response_data2)

if v and len(v) > 0:
    # AI応答がポリシー違反
    status_message2.empty()
    policy_names = [v["name"] for v in v]
    error_msg = f"🚫 AIの回答にDLP違反した内容がありました。表示できません。\n違反ポリシー: {', '.join(policy_names)}"
    
    st.session_state.messages.append({
        "role": "assistant",
        "content": error_msg,
        "violations": v
    })
    
    with st.chat_message("assistant"):
        st.error(error_msg)
else:
    # 正常応答
    status_message2.empty()
    st.success("✅ AI応答のポリシー違反はありませんでした")
    
    st.session_state.messages.append({
        "role": "assistant",
        "content": ai_response,
        "violations": []
    })
    
    with st.chat_message("assistant"):
        st.write(ai_response)
        st.caption(f"⏱️ 応答時間: {elapsed_time:.1f}秒")
