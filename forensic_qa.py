# forensic_qa.py - Interactive Q&A for Forensic Data
import pandas as pd
from report_generator import get_available_ai_backend, get_gemini_client, generate_with_ollama


def answer_forensic_question(question, df, full_forensic_data=None, conversation_history=None):
    """
    Answer investigator questions based strictly on analyzed forensic data.
    
    Args:
        question: The investigator's question
        df: Call log DataFrame
        full_forensic_data: Dict of all extracted forensic data
        conversation_history: List of previous Q&A pairs for context
    
    Returns:
        str: Answer grounded in the forensic data
    """
    try:
        # Determine AI backend
        backend = get_available_ai_backend()
        
        if backend is None:
            return "**ERROR**: No AI backend available for Q&A."
        
        # Get appropriate client
        if backend == "gemini":
            client = get_gemini_client()
        else:
            client = None
        
        # Build data context
        context = f"""You are a forensic analyst assistant. Answer the investigator's question based STRICTLY on the analyzed data provided below. Do not make assumptions beyond what the data shows.

**CRITICAL RULES:**
1. ONLY use information present in the data below
2. If data is insufficient to answer, state that clearly
3. Cite specific evidence (e.g., "Based on call log entry from 2024-01-15...")
4. Distinguish between facts and inferences
5. Keep responses concise but thorough

**AVAILABLE DATA:**

**Call Logs:**
- Total records: {len(df)}
- Date range: {df['datetime'].min()} to {df['datetime'].max()}
- Unique contacts: {df['number'].nunique()}
- Call types: {df['call_type'].value_counts().to_dict()}
- Top 10 contacts: {df['number'].value_counts().head(10).to_dict()}
"""
        
        # Add SMS data if available
        if full_forensic_data and full_forensic_data.get('sms_data'):
            sms_df = pd.DataFrame(full_forensic_data['sms_data'])
            if not sms_df.empty:
                context += f"\n**SMS Messages:**\n- Total: {len(sms_df)}\n- Top contacts: {sms_df['address'].value_counts().head(5).to_dict()}\n"
        
        # Add app data if available
        if full_forensic_data and full_forensic_data.get('apps_data'):
            apps_df = pd.DataFrame(full_forensic_data['apps_data'])
            if not apps_df.empty:
                # Check which column name exists
                pkg_col = 'package' if 'package' in apps_df.columns else ('package_name' if 'package_name' in apps_df.columns else None)
                if pkg_col:
                    context += f"\n**Installed Apps:**\n- Total: {len(apps_df)}\n- Sample apps: {apps_df[pkg_col].head(10).tolist()}\n"
                else:
                    context += f"\n**Installed Apps:**\n- Total: {len(apps_df)}\n"
        
        # Add account data if available
        if full_forensic_data and full_forensic_data.get('parsed_accounts') is not None:
            acc_df = full_forensic_data['parsed_accounts']
            if isinstance(acc_df, pd.DataFrame) and not acc_df.empty:
                context += f"\n**Accounts:**\n- Total: {len(acc_df)}\n- Categories: {acc_df['category'].value_counts().to_dict()}\n"
        
        # Add network/WiFi data
        if full_forensic_data and full_forensic_data.get('wifi_profiles') is not None:
            wifi_df = full_forensic_data['wifi_profiles']
            if isinstance(wifi_df, pd.DataFrame) and not wifi_df.empty:
                context += f"\n**WiFi Networks:**\n- Configured networks: {len(wifi_df)}\n"
        
        # Add browser data
        if full_forensic_data and full_forensic_data.get('browser_searches'):
            browser = str(full_forensic_data['browser_searches'])[:500]
            context += f"\n**Browser Activity:**\n{browser}\n"
        
        # Add conversation history for context
        if conversation_history:
            context += "\n**Previous Questions & Answers:**\n"
            for qa in conversation_history[-3:]:  # Last 3 Q&A pairs
                context += f"Q: {qa['question']}\nA: {qa['answer']}\n\n"
        
        # Build the full prompt
        prompt = f"{context}\n\n**INVESTIGATOR'S QUESTION:**\n{question}\n\n**YOUR ANSWER (based strictly on the data above):**"
        
        # Generate answer using appropriate backend
        if backend == "gemini":
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt
            )
            answer = response.text
        else:  # ollama
            answer = generate_with_ollama(prompt)
        
        return answer
        
    except Exception as e:
        return f"**Error**: Failed to answer question: {str(e)}"
