import streamlit as st
import pandas as pd

with st.sidebar:
    files = st.file_uploader("View parquet files", accept_multiple_files=True)
    uploaded_file = st.selectbox("Pick file to view", files, key="uploaded_file")

if uploaded_file:
    df = pd.read_parquet(uploaded_file)
    st.dataframe(df)