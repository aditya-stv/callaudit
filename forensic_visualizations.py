# forensic_visualizations.py - Visualization functions for forensic analysis

import plotly.graph_objects as go
import plotly.express as px
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import io


def create_timeline_chart(df, incident_datetime=None):
    """Create interactive timeline chart showing call activity over time"""
    if df.empty:
        return None
    
    # Aggregate calls by date
    daily_calls = df.groupby(df['datetime'].dt.date).size().reset_index()
    daily_calls.columns = ['date', 'count']
    
    fig = go.Figure()
    
    # Add main timeline
    fig.add_trace(go.Scatter(
        x=daily_calls['date'],
        y=daily_calls['count'],
        mode='lines+markers',
        name='Call Activity',
        line=dict(color='#007bff', width=2),
        marker=dict(size=6)
    ))
    
    # Add incident marker if provided
    if incident_datetime:
        incident_date = incident_datetime.date()
        fig.add_vline(
            x=incident_date,
            line_dash="dash",
            line_color="red",
            annotation_text="Incident",
            annotation_position="top"
        )
    
    fig.update_layout(
        title='Communication Timeline',
        xaxis_title='Date',
        yaxis_title='Number of Calls',
        hovermode='x unified',
        height=400
    )
    
    return fig


def create_call_type_distribution(df):
    """Create pie chart for call type distribution"""
    if df.empty:
        return None
    
    call_type_counts = df['call_type'].value_counts()
    
    colors = {
        'OUTGOING': '#28a745',
        'INCOMING': '#007bff',
        'MISSED': '#fd7e14',
        'REJECTED': '#dc3545'
    }
    
    color_list = [colors.get(ct, '#6c757d') for ct in call_type_counts.index]
    
    fig = go.Figure(data=[go.Pie(
        labels=call_type_counts.index,
        values=call_type_counts.values,
        marker=dict(colors=color_list),
        hole=0.3
    )])
    
    fig.update_layout(
        title='Call Type Distribution',
        height=400
    )
    
    return fig


def create_hourly_activity_chart(df):
    """Create bar chart showing activity by hour of day"""
    if df.empty:
        return None
    
    hourly_counts = df.groupby(df['datetime'].dt.hour).size().reindex(range(24), fill_value=0)
    
    # Color code hours (night = red, day = blue, evening = orange)
    colors = []
    for hour in range(24):
        if 0 <= hour < 6:
            colors.append('#dc3545')  # Night - red
        elif 6 <= hour < 18:
            colors.append('#007bff')  # Day - blue
        else:
            colors.append('#fd7e14')  # Evening - orange
    
    fig = go.Figure(data=[go.Bar(
        x=list(range(24)),
        y=hourly_counts.values,
        marker_color=colors,
        text=hourly_counts.values,
        textposition='auto'
    )])
    
    fig.update_layout(
        title='Activity by Hour of Day',
        xaxis_title='Hour (0-23)',
        yaxis_title='Number of Calls',
        height=400,
        showlegend=False
    )
    
    return fig


def create_duration_histogram(df):
    """Create histogram of call durations"""
    if df.empty or df['duration_s'].sum() == 0:
        return None
    
    # Filter out zero durations and cap at reasonable max
    durations = df[df['duration_s'] > 0]['duration_s'].clip(upper=3600)
    
    fig = go.Figure(data=[go.Histogram(
        x=durations,
        nbinsx=30,
        marker_color='#007bff',
        opacity=0.7
    )])
    
    fig.update_layout(
        title='Call Duration Distribution',
        xaxis_title='Duration (seconds)',
        yaxis_title='Frequency',
        height=400
    )
    
    return fig


def create_top_contacts_chart(df, top_n=10):
    """Create horizontal bar chart of top contacts"""
    if df.empty:
        return None
    
    contact_counts = df.groupby('number').size().sort_values(ascending=True).tail(top_n)
    
    # Add names if available
    labels = []
    for number in contact_counts.index:
        name = df[df['number'] == number]['saved_name'].iloc[0] if 'saved_name' in df.columns else ''
        if name and name != '':
            labels.append(f"{name}\n({number})")
        else:
            labels.append(number)
    
    fig = go.Figure(data=[go.Bar(
        y=labels,
        x=contact_counts.values,
        orientation='h',
        marker_color='#28a745',
        text=contact_counts.values,
        textposition='auto'
    )])
    
    fig.update_layout(
        title=f'Top {top_n} Contacts',
        xaxis_title='Number of Calls',
        yaxis_title='Contact',
        height=400,
        showlegend=False
    )
    
    return fig


def create_behavioral_heatmap(df):
    """Create heatmap of calls by day of week and hour"""
    if df.empty:
        return None
    
    df_copy = df.copy()
    df_copy['hour'] = df_copy['datetime'].dt.hour
    df_copy['day_of_week'] = df_copy['datetime'].dt.dayofweek
    
    heatmap_data = df_copy.groupby(['day_of_week', 'hour']).size().unstack(fill_value=0)
    
    day_names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    
    fig = go.Figure(data=go.Heatmap(
        z=heatmap_data.values,
        x=list(range(24)),
        y=day_names,
        colorscale='Blues',
        hoverongaps=False
    ))
    
    fig.update_layout(
        title='Activity Heatmap (Day × Hour)',
        xaxis_title='Hour of Day',
        yaxis_title='Day of Week',
        height=400
    )
    
    return fig


def create_burner_phone_chart(burner_phones_df):
    """Create chart showing burner phone suspects"""
    if burner_phones_df.empty:
        return None
    
    top_burners = burner_phones_df.nlargest(10, 'suspicion_score')
    
    fig = go.Figure(data=[go.Bar(
        x=top_burners['number'],
        y=top_burners['suspicion_score'],
        marker_color='#dc3545',
        text=top_burners['suspicion_score'].round(2),
        textposition='auto'
    )])
    
    fig.update_layout(
        title='Burner Phone Suspicion Scores',
        xaxis_title='Phone Number',
        yaxis_title='Suspicion Score',
        height=400,
        showlegend=False
    )
    
    fig.update_xaxes(tickangle=45)
    
    return fig


def save_plotly_as_image(fig, filename):
    """Save plotly figure as PNG image for PDF inclusion"""
    if fig is None:
        return None
    
    try:
        img_bytes = fig.to_image(format="png", width=800, height=500)
        return img_bytes
    except Exception as e:
        print(f"Error saving plotly figure: {e}")
        return None


# ============================================================================
# NEW FORENSIC VISUALIZATIONS
# ============================================================================

def create_sms_activity_chart(sms_df):
    """Create timeline chart for SMS activity"""
    if sms_df is None or sms_df.empty:
        return None
    
    try:
        # Ensure date is datetime
        df = sms_df.copy()
        df['datetime'] = pd.to_datetime(pd.to_numeric(df['date']), unit='ms', errors='coerce')
        df = df.dropna(subset=['datetime'])
        
        # Aggregate by date and type
        daily_sms = df.groupby([df['datetime'].dt.date, 'type']).size().reset_index(name='count')
        daily_sms.columns = ['date', 'type', 'count']
        
        fig = go.Figure()
        
        # Inbox (type=1)
        inbox = daily_sms[daily_sms['type'] == '1']
        fig.add_trace(go.Scatter(
            x=inbox['date'], y=inbox['count'],
            mode='lines+markers', name='Inbox',
            line=dict(color='#007bff')
        ))
        
        # Sent (type=2)
        sent = daily_sms[daily_sms['type'] == '2']
        fig.add_trace(go.Scatter(
            x=sent['date'], y=sent['count'],
            mode='lines+markers', name='Sent',
            line=dict(color='#28a745')
        ))
        
        fig.update_layout(
            title='SMS Activity Timeline',
            xaxis_title='Date',
            yaxis_title='Number of Messages',
            hovermode='x unified',
            height=400
        )
        return fig
    except Exception:
        return None


def create_top_sms_contacts_chart(sms_df, top_n=10):
    """Create bar chart of top SMS contacts"""
    if sms_df is None or sms_df.empty:
        return None
    
    try:
        df = sms_df.copy()
        # Use contact_name if available, otherwise address
        df['display'] = df.apply(lambda r: r.get('contact_name') or r.get('address', 'Unknown'), axis=1)
        
        top_contacts = df['display'].value_counts().head(top_n).sort_values(ascending=True)
        
        fig = go.Figure(data=[go.Bar(
            y=top_contacts.index,
            x=top_contacts.values,
            orientation='h',
            marker_color='#6f42c1',
            text=top_contacts.values,
            textposition='auto'
        )])
        
        fig.update_layout(
            title=f'Top {top_n} SMS Contacts',
            xaxis_title='Message Count',
            yaxis_title='Contact',
            height=400
        )
        return fig
    except Exception:
        return None


def create_browser_activity_chart(searches_raw):
    """Create chart of browser search frequency/intent"""
    if not searches_raw:
        return None
    
    try:
        # Simple extraction of keywords from raw searches output
        # (Assuming rows look like: Row: 0 search=keyword, date=...)
        lines = searches_raw.splitlines()
        searches = []
        for line in lines:
            if 'search=' in line:
                part = line.split('search=')[1].split(',')[0].strip()
                if part: searches.append(part)
        
        if not searches:
            return None
            
        search_counts = pd.Series(searches).value_counts().head(10)
        
        fig = go.Figure(data=[go.Pie(
            labels=search_counts.index,
            values=search_counts.values,
            hole=0.4
        )])
        
        fig.update_layout(
            title='Top Search Keywords',
            height=400
        )
        return fig
    except Exception:
        return None


def create_app_usage_chart(usage_raw):
    """Create chart of top apps by usage frequency from dumpsys usagestats"""
    if not usage_raw:
        return None
    
    try:
        # Parse basic usage counts from dumpsys usagestats
        # Look for patterns like "package=com.android.chrome ... totalTime=..."
        import re
        packages = re.findall(r'package=([a-zA-Z0-9\._]+)', usage_raw)
        if not packages:
            return None
            
        package_counts = pd.Series(packages).value_counts().head(10).sort_values(ascending=True)
        
        fig = go.Figure(data=[go.Bar(
            y=package_counts.index,
            x=package_counts.values,
            orientation='h',
            marker_color='#e83e8c',
            text=package_counts.values,
            textposition='auto'
        )])
        
        fig.update_layout(
            title='Top Apps by Usage (Frequency)',
            xaxis_title='Launch Frequency Estimate',
            yaxis_title='App Package',
            height=400
        )
        return fig
    except Exception:
        return None


def create_calendar_distribution_chart(events_df):
    """Create chart of calendar event types/locations"""
    if events_df is None or events_df.empty:
        return None
    
    try:
        # Distribution by location (as proxy for activity type)
        locations = events_df['eventLocation'].replace('', 'No Location').value_counts().head(10)
        
        fig = go.Figure(data=[go.Pie(
            labels=locations.index,
            values=locations.values,
            hole=0.4
        )])
        
        fig.update_layout(
            title='Calendar Event Locations',
            height=400
        )
        return fig
    except Exception:
        return None


def create_sms_hourly_chart(sms_df):
    """Create chart of SMS activity by hour of day."""
    if sms_df is None or sms_df.empty:
        return None
    
    try:
        df = sms_df.copy()
        if 'datetime' not in df.columns:
            df['datetime'] = pd.to_datetime(pd.to_numeric(df['date']), unit='ms', errors='coerce')
        
        hourly_counts = df.groupby(df['datetime'].dt.hour).size().reindex(range(24), fill_value=0)
        
        fig = go.Figure(data=[go.Bar(
            x=list(range(24)),
            y=hourly_counts.values,
            marker_color='#17a2b8',
            text=hourly_counts.values,
            textposition='auto'
        )])
        
        fig.update_layout(
            title='SMS Activity by Hour of Day',
            xaxis_title='Hour (0-23)',
            yaxis_title='Number of Messages',
            height=400
        )
        return fig
    except Exception:
        return None


def create_sms_length_dist(sms_df):
    """Create histogram of SMS message lengths."""
    if sms_df is None or sms_df.empty:
        return None
    
    try:
        df = sms_df.copy()
        df['length'] = df['body'].apply(lambda x: len(str(x)))
        
        fig = go.Figure(data=[go.Histogram(
            x=df['length'],
            nbinsx=30,
            marker_color='#6c757d',
            opacity=0.7
        )])
        
        fig.update_layout(
            title='SMS Message Length Distribution',
            xaxis_title='Length (characters)',
            yaxis_title='Frequency',
            height=400
        )
        return fig
    except Exception:
        return None


def create_app_category_chart(suspicious_apps_df):
    """Create a pie chart of app forensic categories."""
    if suspicious_apps_df is None or suspicious_apps_df.empty:
        return None
    
    try:
        # Extract primary category from findings
        df = suspicious_apps_df.copy()
        df['category'] = df['findings'].apply(lambda x: x.split(': ')[1] if ': ' in x else 'Other')
        counts = df['category'].value_counts()
        
        import plotly.express as px
        fig = px.pie(
            names=counts.index,
            values=counts.values,
            title='Forensic Application Distribution',
            hole=0.4,
            color_discrete_sequence=px.colors.qualitative.Pastel
        )
        fig.update_layout(height=400)
        return fig
    except Exception:
        return None


def create_log_intensity_chart(log_findings):
    """Create a timeline of log security findings."""
    if not log_findings:
        return None
    
    try:
        import pandas as pd
        import plotly.express as px
        ldf = pd.DataFrame(log_findings)
        cat_counts = ldf['category'].value_counts()
        
        fig = px.bar(
            x=cat_counts.index,
            y=cat_counts.values,
            title='Security Log Event Intensity',
            labels={'x': 'Event Category', 'y': 'Count'},
            color=cat_counts.index,
            color_discrete_sequence=px.colors.qualitative.Safe
        )
        fig.update_layout(height=400)
        return fig
    except Exception:
        return None


def create_browser_domain_pie(domain_df):
    """Create a pie chart of browser domain categories."""
    if domain_df is None or domain_df.empty:
        return None
    
    try:
        import plotly.express as px
        # Group by category
        cat_counts = domain_df.groupby('category')['count'].sum().reset_index()
        
        fig = px.pie(
            cat_counts,
            names='category',
            values='count',
            title='Web Domain Category Distribution',
            hole=0.4,
            color_discrete_sequence=px.colors.qualitative.Prism
        )
        fig.update_layout(height=400)
        return fig
    except Exception:
        return None


def create_wifi_frequency_chart(wifi_df):
    """Create a bar chart of configured SSIDs."""
    if wifi_df is None or wifi_df.empty:
        return None
    
    try:
        import plotly.express as px
        fig = px.bar(
            wifi_df.head(15), 
            x='ssid', 
            title='Configured WiFi Networks (By relevance)',
            labels={'ssid': 'SSID', 'count': 'Connectivity Weight'},
            color_discrete_sequence=['#ffc107']
        )
        fig.update_layout(height=400, xaxis_tickangle=-45)
        return fig
    except Exception:
        return None


def create_bluetooth_category_chart(bt_findings):
    """Create a breakdown of Bluetooth paired device types."""
    if not bt_findings:
        return None
    
    try:
        import pandas as pd
        import plotly.express as px
        df = pd.DataFrame(bt_findings)
        counts = df['category'].value_counts()
        
        fig = px.bar(
            x=counts.index,
            y=counts.values,
            title='Paired Bluetooth Device Categories',
            labels={'x': 'Category', 'y': 'Device Count'},
            color=counts.index,
            color_discrete_sequence=px.colors.qualitative.Pastel
        )
        fig.update_layout(height=400)
        return fig
    except Exception:
        return None


def create_data_usage_bar(net_df):
    """Create a bar chart of top data-consuming apps."""
    if net_df is None or net_df.empty:
        return None
    
    try:
        import plotly.express as px
        # Show top 10
        top_10 = net_df.head(10).copy()
        
        fig = px.bar(
            top_10,
            x='total_mb',
            y='uid',
            orientation='h',
            title='Top Apps by Data Consumption (MB)',
            labels={'total_mb': 'Total MB (Rx+Tx)', 'uid': 'UID / Package'},
            color='total_mb',
            color_continuous_scale='Reds'
        )
        fig.update_layout(height=400, yaxis={'categoryorder':'total ascending'})
        return fig
    except Exception:
        return None


def create_app_foreground_pie(usage_df):
    """Create a pie chart of time spent per app."""
    if usage_df is None or usage_df.empty:
        return None
    
    try:
        import plotly.express as px
        # Group small items into 'Other'
        df = usage_df.copy()
        total_time = df['foreground_time_sec'].sum()
        if total_time == 0: return None
        
        df['percent'] = (df['foreground_time_sec'] / total_time) * 100
        df.loc[df['percent'] < 5, 'package'] = 'Other (Low usage)'
        
        summary = df.groupby('package')['foreground_time_sec'].sum().reset_index()
        
        fig = px.pie(
            summary,
            names='package',
            values='foreground_time_sec',
            title='App Foreground Time Distribution',
            hole=0.4,
            color_discrete_sequence=px.colors.qualitative.Bold
        )
        fig.update_layout(height=400)
        return fig
    except Exception:
        return None


def create_tx_rx_scatter(net_df):
    """Create a scatter plot highlighting Tx/Rx outliers (Exfiltration)."""
    if net_df is None or net_df.empty:
        return None
    
    try:
        import plotly.express as px
        df = net_df.copy()
        fig = px.scatter(
            df,
            x='rx_mb',
            y='tx_mb',
            text='uid',
            title='Data Exfiltration Outlier Analysis (Tx vs Rx)',
            labels={'rx_mb': 'Received (MB)', 'tx_mb': 'Sent (MB)'},
            color='total_mb',
            hover_data=['rx_mb', 'tx_mb', 'total_mb']
        )
        
        # Add a reference line for 1:1 exfiltration boundary
        m = max(df['rx_mb'].max() if not df.empty else 0, df['tx_mb'].max() if not df.empty else 0) or 100
        fig.add_shape(type="line", x0=0, y0=0, x1=m, y1=m,
                      line=dict(color="Gray", dash="dash"))
        
        fig.update_traces(textposition='top center')
        fig.update_layout(height=500)
        return fig
    except Exception:
        return None


def create_account_distribution_pie(account_df):
    """Create a pie chart of account categories."""
    if account_df is None or account_df.empty:
        return None
    
    try:
        import plotly.express as px
        summary = account_df['category'].value_counts().reset_index()
        summary.columns = ['category', 'count']
        
        fig = px.pie(
            summary,
            names='category',
            values='count',
            title='Digital Identity Ecosystem (Account Categories)',
            hole=0.4,
            color_discrete_sequence=px.colors.qualitative.Pastel
        )
        fig.update_layout(height=400)
        return fig
    except Exception:
        return None
