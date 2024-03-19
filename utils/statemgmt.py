import streamlit as st
import pickle
import zlib
import base64

def compress_object(obj):
    # Compresses a Python object and returns a URL-safe encoded version.
    pickled_obj = pickle.dumps(obj)
    compressed_data = zlib.compress(pickled_obj)
    encoded_data = base64.urlsafe_b64encode(compressed_data)
    return encoded_data.decode('utf-8')

def decompress_object(compressed_string):
    # Decompresses a URL-safe encoded Python object.
    decoded_data = base64.urlsafe_b64decode(compressed_string.encode('utf-8'))
    decompressed_data = zlib.decompress(decoded_data)
    obj = pickle.loads(decompressed_data)
    return obj

def load_session():
    if "session" in st.query_params:
        try:
            st.session_state.update(decompress_object(st.query_params["session"]))
        except Exception as e:
            st.exception(e)
            

def save_session():
    session = {key: value for key, value in st.session_state.items()} # convert to normal dict
    st.query_params["session"] = compress_object(session)