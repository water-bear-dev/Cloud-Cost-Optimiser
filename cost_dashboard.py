
import boto3
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

# --- Constants & Configuration ---
PAGE_TITLE = "AWS Cost Intelligence Dashboard"
PAGE_ICON = "💰"
LAYOUT = "wide"

st.set_page_config(page_title=PAGE_TITLE, page_icon=PAGE_ICON, layout=LAYOUT)

# --- Data Model & Mock Data ---

def generate_mock_cost_data(start_date, end_date):
    """
    Generates a mock FactCost dataset with DimDate and DimService for demonstration.
    Schema:
      - Date (datetime)
      - Service (string)
      - Cost (float)
      - Region (string) - simpler to keep flattened for this scale
    """
    services = ['Amazon EC2', 'Amazon RDS', 'Amazon S3', 'Amazon Lambda', 'AWS CloudTrail', 'Amazon CloudWatch', 'Elastic Load Balancing']
    data = []
    
    current_date = start_date
    while current_date <= end_date:
        for service in services:
            # Base cost + randomness + trend
            base_cost = 100 if service == 'Amazon EC2' else 50 if service == 'Amazon RDS' else 10
            random_factor = pd.np.random.uniform(0.8, 1.2)
            
            # Simulate a spike for "Anomaly" detection in one service
            spike = 0
            if service == 'Amazon EC2' and current_date.day == 15:
                spike = 500 
            
            daily_cost = (base_cost * random_factor) + spike
            
            data.append({
                'Date': current_date,
                'Service': service,
                'Cost': daily_cost,
                'Region': 'us-east-1'
            })
        current_date += timedelta(days=1)
        
    return pd.DataFrame(data)

def get_aws_cost_data(session, start_date, end_date):
    """
    Fetches daily cost usage from AWS Cost Explorer.
    """
    ce = session.client('ce')
    try:
        # Convert dates to string format 'YYYY-MM-DD'
        start_str = start_date.strftime('%Y-%m-%d')
        end_str = end_date.strftime('%Y-%m-%d')
        
        response = ce.get_cost_and_usage(
            TimePeriod={'Start': start_str, 'End': end_str},
            Granularity='DAILY',
            Metrics=['UnblendedCost'],
            GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
        )
        
        results = []
        for time_period in response['Results_By_Time']:
            date_val = time_period['TimePeriod']['Start']
            for group in time_period['Groups']:
                service_name = group['Keys'][0]
                cost = float(group['Metrics']['UnblendedCost']['Amount'])
                results.append({
                    'Date': pd.to_datetime(date_val),
                    'Service': service_name,
                    'Cost': cost
                })
        return pd.DataFrame(results)

    except ClientError as e:
        st.error(f"Error fetching Cost Explorer data: {e}")
        return pd.DataFrame()

# --- Helper Functions for Measures ---

def calculate_kpis(df, current_start, current_end, compare_start, compare_end):
    """
    Calculates Total Spend, Previous Period Spend, Delta, and Delta %.
    """
    current_mask = (df['Date'] >= pd.to_datetime(current_start)) & (df['Date'] <= pd.to_datetime(current_end))
    compare_mask = (df['Date'] >= pd.to_datetime(compare_start)) & (df['Date'] <= pd.to_datetime(compare_end))
    
    curr_df = df[current_mask]
    prev_df = df[compare_mask]
    
    curr_total = curr_df['Cost'].sum()
    prev_total = prev_df['Cost'].sum()
    
    delta = curr_total - prev_total
    delta_pct = (delta / prev_total * 100) if prev_total > 0 else 0.0
    
    return curr_total, prev_total, delta, delta_pct

def get_service_comparison(df, current_start, current_end, compare_start, compare_end):
    """
    Groups data by Service and compares current vs previous period.
    Returns a DataFrame with columns: Service, Current Cost, Previous Cost, Delta, % Delta
    """
    current_mask = (df['Date'] >= pd.to_datetime(current_start)) & (df['Date'] <= pd.to_datetime(current_end))
    compare_mask = (df['Date'] >= pd.to_datetime(compare_start)) & (df['Date'] <= pd.to_datetime(compare_end))
    
    curr_group = df[current_mask].groupby('Service')['Cost'].sum().reset_index(name='Current Cost')
    prev_group = df[compare_mask].groupby('Service')['Cost'].sum().reset_index(name='Previous Cost')
    
    merged = pd.merge(curr_group, prev_group, on='Service', how='outer').fillna(0)
    merged['Delta'] = merged['Current Cost'] - merged['Previous Cost']
    merged['% Delta'] = (merged['Delta'] / merged['Previous Cost'].replace(0, 1)) * 100
    
    return merged

# --- Main Application ---

def main():
    st.title(f"{PAGE_ICON} {PAGE_TITLE}")
    
    # --- Sidebar Filters ---
    st.sidebar.title("Filters")
    
    # Date Range Picker
    today = datetime.today()
    default_start = today - timedelta(days=30)
    date_range = st.sidebar.date_input(
        "Select Date Range",
        value=(default_start, today),
        max_value=today
    )
    
    use_demo = st.sidebar.checkbox("Enable Demo Mode", value=True)
    
    if len(date_range) != 2:
        st.info("Please select a valid start and end date.")
        return
    
    start_date, end_date = date_range
    
    # Calculate "Previous Period" automatically (Same duration, immediately preceding)
    duration = end_date - start_date
    prev_end = start_date - timedelta(days=1)
    prev_start = prev_end - duration
    
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"**Current Period:** {start_date} to {end_date}")
    st.sidebar.markdown(f"**Previous Period:** {prev_start} to {prev_end}")

    # --- Data Loading ---
    with st.spinner("Loading financial data..."):
        if use_demo:
            # Generate enough mock data to cover both periods
            # We need mock data from prev_start to end_date
            overall_start = prev_start
            overall_end = end_date
            # Converting date objects to datetime for the generator (if needed) or keeping as date
            # Our generator uses daily increment, so logic is fine.
            # Just ensuring types match for pandas filtering later
            df_main = generate_mock_cost_data(datetime.combine(overall_start, datetime.min.time()), 
                                              datetime.combine(overall_end, datetime.min.time()))
        else:
            session = boto3.Session() # Assume environment creds
            df_main = get_aws_cost_data(session, prev_start, end_date)
            
    if df_main.empty:
        st.warning("No data found for the selected period.")
        return

    # Service Filter (Apply after loading data to knwo available services)
    all_services = sorted(df_main['Service'].unique())
    selected_services = st.sidebar.multiselect("Filter by Service", all_services, default=all_services)
    
    # Filter Data by Service
    df_filtered = df_main[df_main['Service'].isin(selected_services)]

    # --- KPI Cards ---
    curr_spend, prev_spend, delta, delta_pct = calculate_kpis(df_filtered, start_date, end_date, prev_start, prev_end)
    
    kpi1, kpi2, kpi3 = st.columns(3)
    
    kpi1.metric(
        label="Total Spend (Current Period)",
        value=f"${curr_spend:,.2f}",
        delta=f"{delta_pct:.1f}% vs Prev",
        delta_color="inverse" # Red if cost increases, Green if decreases
    )
    
    kpi2.metric(
        label="Total Spend (Previous Period)",
        value=f"${prev_spend:,.2f}"
    )
    
    # Simple Forecast (Naive Projection: Avg Daily Cost * Remaining Days in Month? Or just flat projection)
    # Let's do a simple "Run Rate" -> (Current Spend / Days Passed) * 30
    days_passed = (end_date - start_date).days + 1
    run_rate = (curr_spend / days_passed) * 30
    kpi3.metric(
        label="Est. Monthly Run Rate",
        value=f"${run_rate:,.2f}",
        help="Projected 30-day spend based on current daily average."
    )
    
    st.divider()

    # --- Trend Chart ---
    st.subheader("Daily Spend Trend")
    # Group by Date
    daily_trend = df_filtered.groupby('Date')['Cost'].sum().reset_index()
    
    # Using Plotly for Better Chart
    fig_trend = px.line(daily_trend, x='Date', y='Cost', markers=True, 
                        title="Daily Cloud Cost", 
                        labels={'Cost': 'Spend ($)', 'Date': 'Date'})
    fig_trend.update_traces(line_color='#FF9900', line_width=3) # AWS Orange-ish
    st.plotly_chart(fig_trend, use_container_width=True)
    
    st.divider()
    
    # --- Service Comparisons (Increases / Decreases) ---
    
    service_comp_df = get_service_comparison(df_filtered, start_date, end_date, prev_start, prev_end)
    
    col_left, col_right = st.columns(2)
    
    with col_left:
        st.subheader("📈 Top Cost Increases")
        # Sort by Delta Descending (Positive Delta)
        top_increases = service_comp_df[service_comp_df['Delta'] > 0].sort_values(by='Delta', ascending=False).head(5)
        st.dataframe(
            top_increases.style.format({
                'Current Cost': '${:,.2f}', 
                'Previous Cost': '${:,.2f}', 
                'Delta': '+${:,.2f}', 
                '% Delta': '{:+.1f}%'
            }), 
            use_container_width=True
        )
        
    with col_right:
        st.subheader("📉 Top Cost Decreases")
        # Sort by Delta Ascending (Negative Delta)
        top_decreases = service_comp_df[service_comp_df['Delta'] < 0].sort_values(by='Delta', ascending=True).head(5)
        st.dataframe(
            top_decreases.style.format({
                'Current Cost': '${:,.2f}', 
                'Previous Cost': '${:,.2f}', 
                'Delta': '${:,.2f}', 
                '% Delta': '{:+.1f}%'
            }), 
            use_container_width=True
        )

    st.divider()

    # --- Top 10 Most Expensive Table & Chart ---
    st.subheader("🏆 Top 10 Most Expensive Services")
    top_10 = service_comp_df.sort_values(by='Current Cost', ascending=False).head(10)
    
    col_top_table, col_top_chart = st.columns([0.6, 0.4])
    
    with col_top_table:
        st.dataframe(
            top_10[['Service', 'Current Cost', '% Delta']].style.format({
                'Current Cost': '${:,.2f}', 
                '% Delta': '{:+.1f}%'
            }), 
            use_container_width=True
        )
        
    with col_top_chart:
        fig_bar = px.bar(top_10, x='Current Cost', y='Service', orientation='h', 
                         title="Spend by Service (Top 10)", 
                         text='Current Cost')
        fig_bar.update_traces(texttemplate='$%{text:.2s}', textposition='outside')
        fig_bar.update_layout(yaxis={'categoryorder':'total ascending'})
        st.plotly_chart(fig_bar, use_container_width=True)
        
    st.divider()
    
    # --- Cost Anomalies ---
    st.subheader("🚨 Cost Anomalies (Movers over 20%)")
    # Defined as: Cost > $10 (ignore tiny noise) AND abs(% Delta) > 20%
    anomalies = service_comp_df[
        (service_comp_df['Current Cost'] > 10) & 
        (service_comp_df['% Delta'].abs() > 20.0)
    ].sort_values(by='Delta', ascending=False)
    
    if not anomalies.empty:
        st.dataframe(
            anomalies.style.format({
                'Current Cost': '${:,.2f}', 
                'Previous Cost': '${:,.2f}', 
                'Delta': '${:,.2f}', 
                '% Delta': '{:+.1f}%'
            }).applymap(lambda v: 'color: red;' if v > 0 else 'color: green;', subset=['Delta', '% Delta']),
            use_container_width=True
        )
    else:
        st.success("No significant cost anomalies detected.")

if __name__ == "__main__":
    main()
