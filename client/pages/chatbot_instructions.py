import streamlit as st

from nigol_authentication import nigol_authenticator
from menu import menu
from settings import load_session_state_from_db

from dbt_llm_tools.instructions import ANSWER_QUESTION_INSTRUCTIONS

st.set_page_config(page_title="Chatbot Instructions", page_icon="📝", layout="wide")

# must be logged-in to access this page
if not nigol_authenticator.login():
    exit()

menu()
load_session_state_from_db()

st.header("Chatbot Instructions")

chatbot_instructions = st.text_area(
    "Chatbot Instructions",
    help="These are the first instructions given to the chatbot when it is initialized.",
    value=ANSWER_QUESTION_INSTRUCTIONS,
    height=600,
)
