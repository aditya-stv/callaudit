# forensic_advanced_analysis.py - Law Enforcement Grade Analysis
import pandas as pd
import numpy as np
import networkx as nx
import plotly.graph_objects as go
from datetime import datetime, timedelta
from collections import defaultdict, Counter


def build_communication_network(call_df, sms_df=None):
    """
    Build a network graph from call and SMS data.
    Returns NetworkX graph object.
    """
    G = nx.Graph()
    
    # Add nodes and edges from call logs
    for _, row in call_df.iterrows():
        try:
            number = str(row['number']) if row.get('number') else 'Unknown'
            call_type = str(row.get('call_type', 'UNKNOWN'))
            
            # Try to get duration - support both duration_s (int) and duration (string HH:MM:SS)
            duration = 0
            if 'duration_s' in row and row['duration_s']:
                try:
                    duration = int(row['duration_s'])
                except (ValueError, TypeError):
                    duration = 0
            elif 'duration' in row and row['duration']:
                try:
                    # Try to convert directly to int
                    duration = int(row['duration'])
                except (ValueError, TypeError):
                    duration = 0
            
            if not G.has_node(number):
                G.add_node(number, label=number, calls=0, sms=0, total_duration=0)
            
            # Increment call count and duration
            G.nodes[number]['calls'] += 1
            G.nodes[number]['total_duration'] += duration
            
            # Add edge to "Device Owner" (center node)
            if not G.has_edge('DEVICE_OWNER', number):
                G.add_edge('DEVICE_OWNER', number, weight=0, calls=0, sms=0)
            
            G.edges['DEVICE_OWNER', number]['calls'] += 1
            G.edges['DEVICE_OWNER', number]['weight'] += duration
        except Exception as e:
            # Skip problematic rows but continue processing
            continue
    
    # Add SMS data if available
    if sms_df is not None and not sms_df.empty:
        for _, row in sms_df.iterrows():
            try:
                address = str(row.get('address', 'Unknown'))
                
                if not address or address == 'Unknown':
                    continue
                
                if not G.has_node(address):
                    G.add_node(address, label=address, calls=0, sms=0, total_duration=0)
                
                G.nodes[address]['sms'] += 1
                
                # Ensure DEVICE_OWNER node exists
                if not G.has_node('DEVICE_OWNER'):
                    G.add_node('DEVICE_OWNER', label='DEVICE_OWNER', calls=0, sms=0, total_duration=0)
                
                if not G.has_edge('DEVICE_OWNER', address):
                    G.add_edge('DEVICE_OWNER', address, weight=0, calls=0, sms=0)
                
                G.edges['DEVICE_OWNER', address]['sms'] += 1
                G.edges['DEVICE_OWNER', address]['weight'] += 1  # SMS has weight 1
            except Exception as e:
                # Skip problematic rows but continue processing
                continue
    
    return G


def calculate_network_metrics(G):
    """
    Calculate social network analysis metrics.
    """
    metrics = {}
    
    # Centrality measures
    degree_cent = nx.degree_centrality(G)
    betweenness_cent = nx.betweenness_centrality(G)
    closeness_cent = nx.closeness_centrality(G)
    
    # Find most influential nodes
    top_degree = sorted(degree_cent.items(), key=lambda x: x[1], reverse=True)[:10]
    top_betweenness = sorted(betweenness_cent.items(), key=lambda x: x[1], reverse=True)[:10]
    
    metrics['degree_centrality'] = degree_cent
    metrics['betweenness_centrality'] = betweenness_cent
    metrics['closeness_centrality'] = closeness_cent
    metrics['top_influential'] = top_degree
    metrics['top_bridges'] = top_betweenness
    metrics['total_nodes'] = G.number_of_nodes()
    metrics['total_edges'] = G.number_of_edges()
    
    # Community detection
    try:
        communities = nx.community.greedy_modularity_communities(G)
        metrics['communities'] = list(communities)
        metrics['num_communities'] = len(communities)
    except:
        metrics['communities'] = []
        metrics['num_communities'] = 0
    
    return metrics


def create_interactive_network_graph(G, metrics):
    """
    Create interactive network visualization using Plotly.
    Improved version - filters to show only meaningful connections.
    """
    # Filter graph to show only significant connections (3+ interactions)
    G_filtered = G.copy()
    weak_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get('weight', 0) < 100]
    G_filtered.remove_edges_from(weak_edges)
    
    # Remove isolated nodes
    isolated = [node for node in G_filtered.nodes() if G_filtered.degree(node) == 0 and node != 'DEVICE_OWNER']
    G_filtered.remove_nodes_from(isolated)
    
    # If too many nodes, keep only top N by activity
    if G_filtered.number_of_nodes() > 25:
        # Get node weights
        node_weights = {}
        for node in G_filtered.nodes():
            if node != 'DEVICE_OWNER':
                node_weights[node] = G_filtered.nodes[node].get('calls', 0) + G_filtered.nodes[node].get('sms', 0)
        
        # Keep top 20 + device owner
        top_nodes = sorted(node_weights.items(), key=lambda x: x[1], reverse=True)[:20]
        keep_nodes = [node for node, _ in top_nodes] + ['DEVICE_OWNER']
        remove_nodes = [n for n in G_filtered.nodes() if n not in keep_nodes]
        G_filtered.remove_nodes_from(remove_nodes)
    
    # Use Kamada-Kawai layout for better structure
    try:
        pos = nx.kamada_kawai_layout(G_filtered)
    except:
        pos = nx.spring_layout(G_filtered, k=2, iterations=50, seed=42)
    
    # Create edge traces with labels
    edge_trace = []
    edge_labels_x = []
    edge_labels_y = []
    edge_labels_text = []
    
    for edge in G_filtered.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        
        # Get edge weight for thickness and color
        weight = G.edges[edge].get('weight', 1)
        calls = G.edges[edge].get('calls', 0)
        sms = G.edges[edge].get('sms', 0)
        
        # Color edges based on weight - gradient from cyan (weak) to magenta (strong)
        if weight > 500:
            edge_color = 'rgba(255, 0, 255, 0.8)'  # Magenta - very strong
        elif weight > 300:
            edge_color = 'rgba(255, 50, 150, 0.7)'  # Pink - strong
        elif weight > 150:
            edge_color = 'rgba(100, 150, 255, 0.6)'  # Blue - medium
        else:
            edge_color = 'rgba(0, 255, 255, 0.5)'  # Cyan - weak
        
        edge_trace.append(
            go.Scatter(
                x=[x0, x1, None],
                y=[y0, y1, None],
                mode='lines',
                line=dict(
                    width=min(weight / 80, 12),  # Thicker lines, scale line width
                    color=edge_color
                ),
                hoverinfo='text',
                text=f"{edge[0]} ↔ {edge[1]}<br>Calls: {calls}<br>SMS: {sms}<br>Total Weight: {weight}",
                showlegend=False
            )
        )
    
    # Create node traces
    node_x = []
    node_y = []
    node_text = []
    node_size = []
    node_color = []
    
    # IMPORTANT: Iterate over G_filtered.nodes() since pos was created from G_filtered
    for node in G_filtered.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        
        # Node information - get from original graph G for complete data
        calls = G.nodes[node].get('calls', 0)
        sms = G.nodes[node].get('sms', 0)
        duration = G.nodes[node].get('total_duration', 0)
        
        # Calculate influence score
        influence = metrics['degree_centrality'].get(node, 0) * 100
        
        # Create hover text and assign colors
        if node == 'DEVICE_OWNER':
            text = f"<b>🔴 DEVICE OWNER</b><br>Communications: {G_filtered.degree(node)}"
            size = 70
            color = '#FF0040'  # Bright red for device owner
        else:
            text = f"<b>{node}</b><br>Calls: {calls}<br>SMS: {sms}<br>Duration: {duration}s<br>Influence: {influence:.1f}"
            size = 25 + (calls + sms) * 2  # Size based on activity
            # Use influence for color gradient
            color = influence
        
        node_text.append(text)
        node_size.append(min(size, 60))  # Cap maximum size
        node_color.append(color if isinstance(color, str) else influence)
    
    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=[node if node == 'DEVICE_OWNER' else '' for node in G_filtered.nodes()],
        textposition='top center',
        textfont=dict(
            size=12,
            color='white',
            family='Arial Black'
        ),
        hovertext=node_text,
        marker=dict(
            size=node_size,
            color=node_color,
            colorscale=[
                [0.0, '#00FFFF'],   # Cyan - low influence
                [0.2, '#00FF00'],   # Green
                [0.4, '#FFFF00'],   # Yellow
                [0.6, '#FF8C00'],   # Orange  
                [0.8, '#FF4500'],   # Red-orange
                [1.0, '#FF0080']    # Hot pink - high influence
            ],
            showscale=True,
            colorbar=dict(
                title=dict(
                    text="Influence<br>Score",
                    side='right',
                    font=dict(color='white', size=11)
                ),
                tickmode='linear',
                tick0=0,
                dtick=20,
                thickness=20,
                len=0.7,
                bgcolor='rgba(40, 40, 40, 0.8)',
                bordercolor='#00FFFF',
                borderwidth=2,
                tickfont=dict(color='white', size=10)
            ),
            line=dict(width=3, color='#00FFFF')  # Cyan border
        ),
        showlegend=False
    )
    
    # Create figure
    fig = go.Figure(data=edge_trace + [node_trace])
    
    fig.update_layout(
        title=dict(
            text="<b>🕸️ Social Network Analysis</b><br><sub>Interactive Contact Network Graph - Forensic Grade</sub>",
            x=0.5,
            xanchor='center',
            font=dict(size=22, color='#00FFFF', family='Arial Black')
        ),
        showlegend=False,
        hovermode='closest',
        margin=dict(b=20, l=5, r=5, t=90),
        xaxis=dict(
            showgrid=False, 
            zeroline=False, 
            showticklabels=False,
            color='#00FFFF'
        ),
        yaxis=dict(
            showgrid=False, 
            zeroline=False, 
            showticklabels=False,
            color='#00FFFF'
        ),
        plot_bgcolor='#0a0a0a',  # Very dark background
        paper_bgcolor='#1a1a1a',  # Dark grey paper
        font=dict(color='white'),
        height=750
    )
    
    return fig


def calculate_contact_risk_scores(call_df, sms_df=None, apps_df=None):
    """
    Calculate risk score for each contact based on multiple factors.
    Returns DataFrame with contacts and their risk scores.
    """
    risk_scores = []
    
    # Analyze call patterns
    for number in call_df['number'].unique():
        contact_calls = call_df[call_df['number'] == number]
        
        score = 0
        reasons = []
        
        # Factor 1: Late night calls (00:00 - 05:00)
        if 'datetime' in contact_calls.columns:
            try:
                late_night = contact_calls[contact_calls['datetime'].dt.hour < 5].shape[0]
                if late_night > 0:
                    score += late_night * 10
                    reasons.append(f"{late_night} late-night calls")
            except (AttributeError, TypeError):
                pass  # Skip if datetime parsing fails
        
        # Factor 2: Very short calls (potential burner)
        try:
            # Ensure duration is numeric
            durations = pd.to_numeric(contact_calls['duration'], errors='coerce').fillna(0)
            short_calls = (durations < 10).sum()
            if short_calls > 5:
                score += 15
                reasons.append(f"{short_calls} very short calls (<10s)")
        except Exception:
            pass
        
        # Factor 3: High frequency in short time
        if len(contact_calls) > 20:
            score += 20
            reasons.append(f"High frequency ({len(contact_calls)} calls)")
        
        # Factor 4: Unknown number (no name)
        if number.startswith('+') or number.isdigit():
            score += 10
            reasons.append("Unknown/unsaved number")
        
        # Factor 5: Check if SMS exists for same number
        if sms_df is not None and not sms_df.empty:
            sms_count = sms_df[sms_df['address'] == number].shape[0]
            if sms_count == 0 and len(contact_calls) > 5:
                score += 15
                reasons.append("Calls only, no SMS (suspicious)")
        
        # Normalize score to 0-100
        final_score = min(score, 100)
        
        # Safe duration sum
        try:
            total_duration = pd.to_numeric(contact_calls['duration'], errors='coerce').fillna(0).sum()
        except Exception:
            total_duration = 0
        
        risk_scores.append({
            'contact': number,
            'risk_score': final_score,
            'call_count': len(contact_calls),
            'total_duration': int(total_duration),
            'reasons': '; '.join(reasons) if reasons else 'No major risk factors',
            'risk_level': 'HIGH' if final_score > 60 else ('MEDIUM' if final_score > 30 else 'LOW')
        })
    
    return pd.DataFrame(risk_scores).sort_values('risk_score', ascending=False)


def create_timeline_view(call_df, sms_df=None, apps_df=None):
    """
    Create unified timeline of all events.
    Returns interactive Plotly timeline.
    """
    timeline_events = []
    
    # Add call events
    for _, row in call_df.iterrows():
        timeline_events.append({
            'timestamp': row['datetime'],
            'type': 'Call',
            'detail': f"{row['call_type']} - {row['number']} ({row['duration']}s)",
            'source': 'Call Log',
            'color': 'blue'
        })
    
    # Add SMS events
    if sms_df is not None and not sms_df.empty and 'datetime' in sms_df.columns:
        for _, row in sms_df.iterrows():
            msg_type = "Inbox" if row.get('type') == '1' else "Sent"
            timeline_events.append({
                'timestamp': row['datetime'],
                'type': 'SMS',
                'detail': f"{msg_type} - {row['address']}",
                'source': 'SMS',
                'color': 'green'
            })
    
    # Convert to DataFrame
    timeline_df = pd.DataFrame(timeline_events).sort_values('timestamp')
    
    # Create interactive timeline using scatter plot
    fig = go.Figure()
    
    for event_type in timeline_df['type'].unique():
        df_type = timeline_df[timeline_df['type'] == event_type]
        
        fig.add_trace(go.Scatter(
            x=df_type['timestamp'],
            y=[event_type] * len(df_type),
            mode='markers',
            name=event_type,
            text=df_type['detail'],
            hovertemplate='<b>%{y}</b><br>%{text}<br>%{x}<extra></extra>',
            marker=dict(
                size=10,
                line=dict(width=2, color='white')
            )
        ))
    
    fig.update_layout(
        title="<b>Unified Timeline Reconstruction</b><br><sub>All Communication Events</sub>",
        xaxis_title="Time",
        yaxis_title="Event Type",
        hovermode='closest',
        height=500,
        showlegend=True
    )
    
    return fig, timeline_df


# ========== PHASE 2: CORRELATION & PATTERN ANALYSIS ==========

def cross_source_correlation(call_df, sms_df=None, apps_df=None, browser_data=None, wifi_data=None):
    import pandas as pd
    correlations = []
    
    # Correlation 1: Call + SMS to same contact
    if sms_df is not None and not sms_df.empty:
        call_numbers = set(call_df['number'].unique())
        sms_numbers = set(sms_df['address'].unique())
        
        # Contacts appearing in both
        both_contacts = call_numbers.intersection(sms_numbers)
        
        for contact in both_contacts:
            call_count = len(call_df[call_df['number'] == contact])
            sms_count = len(sms_df[sms_df['address'] == contact])
            
            correlations.append({
                'type': 'Multi-Channel Communication',
                'source_1': 'Calls',
                'source_2': 'SMS',
                'detail': f'Contact {contact}',
                'strength': min(call_count + sms_count, 100),
                'description': f'{call_count} calls + {sms_count} messages',
                'significance': 'HIGH' if (call_count + sms_count) > 20 else 'MEDIUM'
            })
    
    # Correlation 2: App installation near first contact
    if apps_df is not None and not apps_df.empty and 'datetime' in call_df.columns:
        # Check for messaging apps
        pkg_col = 'package' if 'package' in apps_df.columns else 'package_name' if 'package_name' in apps_df.columns else None
        if pkg_col:
            messaging_apps = apps_df[apps_df[pkg_col].str.contains(
                'whatsapp|telegram|signal|messenger|viber', case=False, na=False
            )]
            
            if not messaging_apps.empty:
                correlations.append({
                    'type': 'Privacy App Usage',
                    'source_1': 'Apps',
                    'source_2': 'Communication',
                    'detail': 'Encrypted messaging apps',
                    'strength': 80,
                    'description': f"Found {len(messaging_apps)} encrypted messaging apps",
                    'significance': 'HIGH'
                })
    
    # Correlation 3: Silent periods across all sources
    if 'datetime' in call_df.columns:
        sorted_df = call_df.sort_values('datetime')
        time_diffs = sorted_df['datetime'].diff()
        large_gaps = time_diffs[time_diffs > pd.Timedelta(hours=12)]
        
        if len(large_gaps) > 0:
            correlations.append({
                'type': 'Activity Gap',
                'source_1': 'Timeline',
                'source_2': 'All Sources',
                'detail': f'{len(large_gaps)} silent periods',
                'strength': 70,
                'description': f'Longest gap: {large_gaps.max()}',
                'significance': 'MEDIUM'
            })
    
    return pd.DataFrame(correlations)


def analyze_communication_patterns(call_df, sms_df=None):
    patterns = {}
    
    if 'datetime' not in call_df.columns:
        return patterns, None
    
    # Extract temporal features
    call_df['hour'] = call_df['datetime'].dt.hour
    call_df['day_of_week'] = call_df['datetime'].dt.dayofweek
    call_df['date'] = call_df['datetime'].dt.date
    
    # Pattern 1: Hourly distribution
    hourly_pattern = call_df.groupby('hour').size()
    patterns['most_active_hour'] = int(hourly_pattern.idxmax())
    patterns['least_active_hour'] = int(hourly_pattern.idxmin())
    
    # Pattern 2: Day of week pattern
    dow_pattern = call_df.groupby('day_of_week').size()
    patterns['most_active_day'] = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][dow_pattern.idxmax()]
    
    # Pattern 3: Frequency spikes
    daily_counts = call_df.groupby('date').size()
    mean_daily = daily_counts.mean()
    std_daily = daily_counts.std()
    spikes = daily_counts[daily_counts > mean_daily + 2 * std_daily]
    patterns['spike_days'] = len(spikes)
    patterns['spike_dates'] = spikes.index.tolist() if len(spikes) > 0 else []
    
    # Pattern 4: Late night activity
    late_night = call_df[call_df['hour'] < 5]
    patterns['late_night_count'] = len(late_night)
    patterns['late_night_percentage'] = (len(late_night) / len(call_df) * 100) if len(call_df) > 0 else 0
    
    # Create heatmap
    pivot_data = call_df.groupby(['day_of_week', 'hour']).size().reset_index(name='count')
    heatmap_data = pivot_data.pivot(index='day_of_week', columns='hour', values='count').fillna(0)
    
    fig = go.Figure(data=go.Heatmap(
        z=heatmap_data.values,
        x=[f"{h}:00" for h in range(24)],
        y=['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'],
        colorscale='Reds',
        hoverongaps=False,
        hovertemplate='Day: %{y}<br>Hour: %{x}<br>Communications: %{z}<extra></extra>'
    ))
    
    fig.update_layout(
        title='<b>Communication Pattern Heatmap</b><br><sub>Activity by Day and Hour</sub>',
        xaxis_title='Hour of Day',
        yaxis_title='Day of Week',
        height=400
    )
    
    return patterns, fig


def detect_behavioral_anomalies(call_df, sms_df=None):
    anomalies = []
    
    if 'datetime' not in call_df.columns:
        return pd.DataFrame(anomalies), None
    
    # Establish baseline behavior
    try:
        call_df['hour'] = pd.to_datetime(call_df['datetime']).dt.hour
    except Exception:
        call_df['hour'] = 0
    
    try:
        call_df['date'] = pd.to_datetime(call_df['datetime']).dt.date
    except Exception:
        call_df['date'] = pd.Timestamp.now().date()
    
    # Anomaly 1: Unusual time communications
    try:
        late_night_calls = call_df[(call_df['hour'] >= 0) & (call_df['hour'] < 5)]
        for _, call in late_night_calls.iterrows():
            try:
                time_str = pd.to_datetime(call['datetime']).strftime('%H:%M')
            except:
                time_str = "unknown"
            
            anomalies.append({
                'timestamp': pd.to_datetime(call['datetime']),
                'type': 'Late Night Activity',
                'detail': f"Call to {call['number']} at {time_str}",
                'severity': 'HIGH',
                'score': 85
            })
    except Exception:
        pass
    
    # Anomaly 2: Frequency spikes
    daily_counts = call_df.groupby('date').size()
    mean_daily = daily_counts.mean()
    std_daily = daily_counts.std()
    
    for date, count in daily_counts.items():
        if count > mean_daily + 2 * std_daily:
            anomalies.append({
                'timestamp': pd.Timestamp(date),
                'type': 'Frequency Spike',
                'detail': f"{count} communications (avg: {mean_daily:.1f})",
                'severity': 'MEDIUM',
                'score': min(((count - mean_daily) / std_daily) * 20, 100)
            })
    
    # Anomaly 3: Very short calls (burner indicator)
    durations = pd.to_numeric(call_df['duration'], errors='coerce').fillna(0)
    short_calls_count = (durations < 10).sum()
    if short_calls_count > len(call_df) * 0.3:
        anomalies.append({
            'timestamp': call_df['datetime'].max(),
            'type': 'Burner Phone Pattern',
            'detail': f"{short_calls_count} very short calls (<10s)",
            'severity': 'CRITICAL',
            'score': 95
        })
    
    anomaly_df = pd.DataFrame(anomalies).sort_values('score', ascending=False) if anomalies else pd.DataFrame(columns=['timestamp', 'type', 'detail', 'severity', 'score'])
    
    # Create timeline visualization
    if not anomaly_df.empty:
        fig = go.Figure()
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            df_sev = anomaly_df[anomaly_df['severity'] == severity]
            if not df_sev.empty:
                fig.add_trace(go.Scatter(
                    x=df_sev['timestamp'],
                    y=df_sev['score'],
                    mode='markers',
                    name=severity,
                    text=df_sev['detail'],
                    hovertemplate='<b>%{text}</b><br>Score: %{y}<br>%{x}<extra></extra>',
                    marker=dict(size=12, line=dict(width=2, color='white'))
                ))
        
        fig.update_layout(
            title='<b>Behavioral Anomaly Timeline</b><br><sub>Suspicious Activity Detection</sub>',
            xaxis_title='Time',
            yaxis_title='Anomaly Score',
            hovermode='closest',
            height=400
        )
    else:
        fig = None
    
    return anomaly_df, fig


