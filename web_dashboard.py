#!/usr/bin/env python3
"""
Web Dashboard for Security Monitoring Dashboard
Built with Plotly Dash for interactive security analytics
"""

import dash
from dash import dcc, html, Input, Output, dash_table
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime, timedelta
import dash_bootstrap_components as dbc

# Add src to path
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__)))

from src.database.database import db_manager
from src.database.models import SecurityEvent, Incident, UserBaseline
from src.dashboard.report_generator import SecurityReportGenerator

# Initialize Dash app with Bootstrap theme
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
app.title = "Security Monitoring Dashboard"

# Initialize report generator
report_generator = SecurityReportGenerator()

def get_kpi_data():
    """Get KPI metrics for dashboard"""
    session = db_manager.get_session()
    try:
        # Get counts from last 24 hours
        yesterday = datetime.utcnow() - timedelta(days=1)
        
        total_events = session.query(SecurityEvent).filter(
            SecurityEvent.timestamp >= yesterday
        ).count()
        
        high_risk_events = session.query(SecurityEvent).filter(
            SecurityEvent.timestamp >= yesterday,
            SecurityEvent.risk_score >= 6.0
        ).count()
        
        open_incidents = session.query(Incident).filter(
            Incident.status == 'open'
        ).count()
        
        critical_incidents = session.query(Incident).filter(
            Incident.status == 'open',
            Incident.severity == 'critical'
        ).count()
        
        return {
            'total_events': total_events,
            'high_risk_events': high_risk_events,
            'open_incidents': open_incidents,
            'critical_incidents': critical_incidents
        }
    finally:
        session.close()

def get_events_timeline():
    """Get events timeline data"""
    session = db_manager.get_session()
    try:
        # Get events from last 7 days using SQLAlchemy
        week_ago = datetime.utcnow() - timedelta(days=7)
        
        from src.database.models import SecurityEvent
        from sqlalchemy import func
        
        results = session.query(
            func.date(SecurityEvent.timestamp).label('date'),
            func.count(SecurityEvent.id).label('count'),
            func.avg(SecurityEvent.risk_score).label('avg_risk')
        ).filter(
            SecurityEvent.timestamp >= week_ago
        ).group_by(
            func.date(SecurityEvent.timestamp)
        ).order_by('date').all()
        
        # Convert to DataFrame
        data = []
        for row in results:
            data.append({
                'date': str(row.date),
                'count': row.count,
                'avg_risk': float(row.avg_risk) if row.avg_risk else 0
            })
        
        return pd.DataFrame(data)
        
    except Exception as e:
        print(f"Error in get_events_timeline: {e}")
        return pd.DataFrame()
    finally:
        session.close()

def get_top_users():
    """Get top risk users"""
    session = db_manager.get_session()
    try:
        from src.database.models import SecurityEvent
        from sqlalchemy import func
        
        week_ago = datetime.utcnow() - timedelta(days=7)
        
        results = session.query(
            SecurityEvent.user_id,
            func.count(SecurityEvent.id).label('event_count'),
            func.avg(SecurityEvent.risk_score).label('avg_risk_score')
        ).filter(
            SecurityEvent.user_id.isnot(None),
            SecurityEvent.timestamp >= week_ago
        ).group_by(
            SecurityEvent.user_id
        ).order_by(
            func.avg(SecurityEvent.risk_score).desc()
        ).limit(10).all()
        
        # Convert to DataFrame
        data = []
        for row in results:
            data.append({
                'user_id': row.user_id,
                'event_count': row.event_count,
                'avg_risk_score': float(row.avg_risk_score) if row.avg_risk_score else 0
            })
        
        return pd.DataFrame(data)
        
    except Exception as e:
        print(f"Error in get_top_users: {e}")
        return pd.DataFrame()
    finally:
        session.close()

def get_incident_data():
    """Get incident data"""
    session = db_manager.get_session()
    try:
        from src.database.models import Incident
        
        results = session.query(Incident).order_by(
            Incident.created_timestamp.desc()
        ).limit(20).all()
        
        # Convert to DataFrame
        data = []
        for incident in results:
            data.append({
                'incident_id': incident.incident_id,
                'title': incident.title,
                'severity': incident.severity,
                'status': incident.status,
                'created_timestamp': incident.created_timestamp.isoformat() if incident.created_timestamp else '',
                'risk_score': float(incident.risk_score) if incident.risk_score else 0
            })
        
        return pd.DataFrame(data)
        
    except Exception as e:
        print(f"Error in get_incident_data: {e}")
        return pd.DataFrame()
    finally:
        session.close()

def get_top_ips():
    """Get top suspicious IP addresses"""
    session = db_manager.get_session()
    try:
        from src.database.models import SecurityEvent
        from sqlalchemy import func
        
        week_ago = datetime.utcnow() - timedelta(days=7)
        
        results = session.query(
            SecurityEvent.source_ip,
            func.count(SecurityEvent.id).label('event_count'),
            func.avg(SecurityEvent.risk_score).label('avg_risk_score'),
            func.max(SecurityEvent.risk_score).label('max_risk_score')
        ).filter(
            SecurityEvent.source_ip.isnot(None),
            SecurityEvent.timestamp >= week_ago,
            SecurityEvent.risk_score > 0
        ).group_by(
            SecurityEvent.source_ip
        ).order_by(
            func.avg(SecurityEvent.risk_score).desc()
        ).limit(15).all()
        
        # Convert to DataFrame
        data = []
        for row in results:
            data.append({
                'source_ip': row.source_ip,
                'event_count': row.event_count,
                'avg_risk_score': float(row.avg_risk_score) if row.avg_risk_score else 0,
                'max_risk_score': float(row.max_risk_score) if row.max_risk_score else 0,
                'threat_level': 'CRITICAL' if row.avg_risk_score >= 8.0 else 
                              'HIGH' if row.avg_risk_score >= 6.0 else 
                              'MEDIUM' if row.avg_risk_score >= 4.0 else 'LOW',
                'ip_type': 'External' if not (row.source_ip.startswith('192.168.') or 
                                            row.source_ip.startswith('10.') or 
                                            row.source_ip.startswith('172.16.')) else 'Internal'
            })
        
        return pd.DataFrame(data)
        
    except Exception as e:
        print(f"Error in get_top_ips: {e}")
        return pd.DataFrame()
    finally:
        session.close()

def get_mitre_techniques():
    """Get MITRE ATT&CK techniques detected"""
    session = db_manager.get_session()
    try:
        from src.database.models import SecurityEvent
        from sqlalchemy import func
        
        week_ago = datetime.utcnow() - timedelta(days=7)
        
        results = session.query(
            SecurityEvent.mitre_technique,
            SecurityEvent.mitre_tactic,
            func.count(SecurityEvent.id).label('count'),
            func.avg(SecurityEvent.risk_score).label('avg_risk')
        ).filter(
            SecurityEvent.mitre_technique.isnot(None),
            SecurityEvent.timestamp >= week_ago
        ).group_by(
            SecurityEvent.mitre_technique,
            SecurityEvent.mitre_tactic
        ).order_by(
            func.count(SecurityEvent.id).desc()
        ).all()
        
        # Convert to DataFrame
        data = []
        for row in results:
            data.append({
                'technique': row.mitre_technique,
                'tactic': row.mitre_tactic,
                'count': row.count,
                'avg_risk': float(row.avg_risk) if row.avg_risk else 0
            })
        
        return pd.DataFrame(data)
        
    except Exception as e:
        print(f"Error in get_mitre_techniques: {e}")
        return pd.DataFrame()
    finally:
        session.close()

# Define layout with tabs
app.layout = dbc.Container([
    # Header
    dbc.Row([
        dbc.Col([
            html.H1("Security Monitoring Dashboard", className="text-center mb-2"),
            html.P("Real-time security analytics and threat detection", className="text-center text-muted")
        ])
    ]),
    
    # KPI Cards (always visible)
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4(id="total-events", className="card-title text-primary"),
                    html.P("Total Events (24h)", className="card-text small")
                ])
            ], outline=True, color="primary")
        ], md=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4(id="high-risk-events", className="card-title text-warning"),
                    html.P("High Risk Events", className="card-text small")
                ])
            ], outline=True, color="warning")
        ], md=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4(id="open-incidents", className="card-title text-info"),
                    html.P("Open Incidents", className="card-text small")
                ])
            ], outline=True, color="info")
        ], md=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4(id="critical-incidents", className="card-title text-danger"),
                    html.P("Critical Incidents", className="card-text small")
                ])
            ], outline=True, color="danger")
        ], md=3)
    ], className="mb-4"),
    
    # Tabs
    dbc.Tabs([
        # Overview Tab
        dbc.Tab(label="Overview", tab_id="overview", children=[
            html.Div([
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader("Security Events Timeline"),
                            dbc.CardBody([
                                dcc.Graph(id="events-timeline")
                            ])
                        ])
                    ], md=8),
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader("Top Risk Users"),
                            dbc.CardBody([
                                dcc.Graph(id="top-users-chart")
                            ])
                        ])
                    ], md=4)
                ], className="mb-4"),
            ])
        ]),
        
        # Threat Intelligence Tab
        dbc.Tab(label="Threat Intelligence", tab_id="threats", children=[
            html.Div([
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader("Suspicious IP Addresses"),
                            dbc.CardBody([
                                dash_table.DataTable(
                                    id="top-ips-table",
                                    columns=[
                                        {"name": "IP Address", "id": "source_ip"},
                                        {"name": "Type", "id": "ip_type"},
                                        {"name": "Events", "id": "event_count"},
                                        {"name": "Avg Risk", "id": "avg_risk_score", "type": "numeric", "format": {"specifier": ".1f"}},
                                        {"name": "Max Risk", "id": "max_risk_score", "type": "numeric", "format": {"specifier": ".1f"}},
                                        {"name": "Threat Level", "id": "threat_level"}
                                    ],
                                    style_cell={'textAlign': 'left', 'fontSize': '14px', 'padding': '10px'},
                                    style_data_conditional=[
                                        {
                                            'if': {'filter_query': '{threat_level} = CRITICAL'},
                                            'backgroundColor': '#ffebee',
                                            'color': 'darkred',
                                            'fontWeight': 'bold'
                                        },
                                        {
                                            'if': {'filter_query': '{threat_level} = HIGH'},
                                            'backgroundColor': '#fff3e0',
                                            'color': 'darkorange',
                                        },
                                        {
                                            'if': {'filter_query': '{ip_type} = External'},
                                            'backgroundColor': '#f3e5f5',
                                            'color': 'purple',
                                        }
                                    ],
                                    sort_action="native",
                                    page_size=15
                                )
                            ])
                        ])
                    ], md=8),
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader("MITRE ATT&CK Techniques"),
                            dbc.CardBody([
                                dcc.Graph(id="mitre-techniques-chart")
                            ])
                        ])
                    ], md=4)
                ])
            ])
        ]),
        
        # Incidents Tab
        dbc.Tab(label="Incidents", tab_id="incidents", children=[
            html.Div([
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader("Recent Security Incidents"),
                            dbc.CardBody([
                                dash_table.DataTable(
                                    id="incidents-table",
                                    columns=[
                                        {"name": "Incident ID", "id": "incident_id"},
                                        {"name": "Title", "id": "title"},
                                        {"name": "Severity", "id": "severity"},
                                        {"name": "Status", "id": "status"},
                                        {"name": "Risk Score", "id": "risk_score", "type": "numeric", "format": {"specifier": ".1f"}},
                                        {"name": "Created", "id": "created_timestamp"}
                                    ],
                                    style_cell={'textAlign': 'left', 'fontSize': '14px', 'padding': '10px'},
                                    style_data_conditional=[
                                        {
                                            'if': {'filter_query': '{severity} = critical'},
                                            'backgroundColor': '#ffebee',
                                            'color': 'darkred',
                                            'fontWeight': 'bold'
                                        },
                                        {
                                            'if': {'filter_query': '{severity} = high'},
                                            'backgroundColor': '#fff3e0',
                                            'color': 'darkorange',
                                        }
                                    ],
                                    page_size=15,
                                    sort_action="native"
                                )
                            ])
                        ])
                    ])
                ])
            ])
        ])
    ], active_tab="overview", className="mb-4"),
    
    # Auto-refresh interval
    dcc.Interval(
        id='interval-component',
        interval=30*1000,  # 30 seconds
        n_intervals=0
    )
    
], fluid=True)

# Callbacks
@app.callback(
    [Output('total-events', 'children'),
     Output('high-risk-events', 'children'),
     Output('open-incidents', 'children'),
     Output('critical-incidents', 'children')],
    [Input('interval-component', 'n_intervals')]
)
def update_kpis(n):
    kpi_data = get_kpi_data()
    return (
        str(kpi_data['total_events']),
        str(kpi_data['high_risk_events']),
        str(kpi_data['open_incidents']),
        str(kpi_data['critical_incidents'])
    )

@app.callback(
    Output('events-timeline', 'figure'),
    [Input('interval-component', 'n_intervals')]
)
def update_events_timeline(n):
    df = get_events_timeline()
    
    if df.empty:
        # Return empty chart if no data
        fig = go.Figure()
        fig.add_annotation(
            text="No data available",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(size=16)
        )
        return fig
    
    fig = go.Figure()
    
    # Add event count line
    fig.add_trace(go.Scatter(
        x=df['date'],
        y=df['count'],
        mode='lines+markers',
        name='Event Count',
        line=dict(color='#1f77b4', width=3),
        yaxis='y'
    ))
    
    # Add average risk score line
    fig.add_trace(go.Scatter(
        x=df['date'],
        y=df['avg_risk'],
        mode='lines+markers',
        name='Average Risk Score',
        line=dict(color='#ff7f0e', width=3),
        yaxis='y2'
    ))
    
    fig.update_layout(
        xaxis_title="Date",
        yaxis=dict(title="Event Count", side='left'),
        yaxis2=dict(title="Average Risk Score", side='right', overlaying='y'),
        hovermode='x unified',
        height=400
    )
    
    return fig

@app.callback(
    Output('top-users-chart', 'figure'),
    [Input('interval-component', 'n_intervals')]
)
def update_top_users(n):
    df = get_top_users()
    
    if df.empty:
        fig = go.Figure()
        fig.add_annotation(
            text="No user data available",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(size=14)
        )
        return fig
    
    fig = px.bar(
        df.head(8), 
        x='avg_risk_score',
        y='user_id',
        orientation='h',
        title="",
        color='avg_risk_score',
        color_continuous_scale='Reds'
    )
    
    fig.update_layout(
        height=400,
        yaxis=dict(categoryorder='total ascending'),
        coloraxis_showscale=False
    )
    
    return fig

@app.callback(
    Output('incidents-table', 'data'),
    [Input('interval-component', 'n_intervals')]
)
def update_incidents_table(n):
    df = get_incident_data()
    
    if df.empty:
        return []
    
    # Format timestamp
    if not df.empty and 'created_timestamp' in df.columns:
        df['created_timestamp'] = pd.to_datetime(df['created_timestamp'], errors='coerce').dt.strftime('%m-%d %H:%M')
    
    return df.to_dict('records')

@app.callback(
    Output('top-ips-table', 'data'),
    [Input('interval-component', 'n_intervals')]
)
def update_top_ips_table(n):
    df = get_top_ips()
    
    if df.empty:
        return []
    
    return df.to_dict('records')

@app.callback(
    Output('mitre-techniques-chart', 'figure'),
    [Input('interval-component', 'n_intervals')]
)
def update_mitre_chart(n):
    df = get_mitre_techniques()
    
    if df.empty:
        fig = go.Figure()
        fig.add_annotation(
            text="No MITRE data available",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(size=14)
        )
        return fig
    
    # Create horizontal bar chart for MITRE techniques
    fig = go.Figure()
    
    # Color map for tactics
    tactic_colors = {
        'Initial Access': '#ff6b6b',
        'Execution': '#4ecdc4', 
        'Persistence': '#45b7d1',
        'Privilege Escalation': '#f9ca24',
        'Defense Evasion': '#f0932b',
        'Credential Access': '#eb4d4b',
        'Discovery': '#6c5ce7',
        'Lateral Movement': '#a29bfe',
        'Collection': '#fd79a8',
        'Command and Control': '#00b894',
        'Exfiltration': '#00cec9',
        'Impact': '#e17055'
    }
    
    for tactic in df['tactic'].unique():
        tactic_data = df[df['tactic'] == tactic]
        fig.add_trace(go.Bar(
            y=tactic_data['technique'],
            x=tactic_data['count'],
            name=tactic,
            orientation='h',
            marker_color=tactic_colors.get(tactic, '#74b9ff'),
            text=tactic_data['count'],
            textposition='auto',
        ))
    
    fig.update_layout(
        title="MITRE ATT&CK Techniques Detected",
        xaxis_title="Detection Count",
        yaxis_title="Technique",
        height=400,
        showlegend=True,
        barmode='stack'
    )
    
    return fig

def main():
    print("Starting Security Monitoring Web Dashboard...")
    print("Dashboard will be available at: http://localhost:8050")
    print("Auto-refresh enabled (30 seconds)")
    
    # Ensure database is initialized
    try:
        db_manager.create_tables()
        print("Database initialized")
    except Exception as e:
        print(f"Database warning: {e}")
    
    app.run(debug=True, host='0.0.0.0', port=8050)

if __name__ == "__main__":
    main()