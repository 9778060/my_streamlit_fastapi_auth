import streamlit as st
from auth.authenticate import init_authentication

authenticator = init_authentication()

try:
    name, authentication_status, username = authenticator.login('Login', 'main')
except Exception as e:
    st.error(e)

if st.session_state["authentication_status"]:
    authenticator.logout('Logout', 'main')
    st.write(f'Welcome *{st.session_state["name"]}*')
    st.title('Some content')
elif st.session_state["authentication_status"] is False:
    st.error('Username/password is incorrect')
elif st.session_state["authentication_status"] is None:
    st.warning('Please enter your username and password')

if st.session_state["authentication_status"]:
    try:
        if authenticator.reset_password(username, 'Reset password'):
            st.success('Password modified successfully')
    except Exception as e:
        st.error(e)

    try:
        if authenticator.update_user_details(username, 'Update user details'):
            st.success('Entries updated successfully')
    except Exception as e:
        st.error(e)

else:
    try:
        if authenticator.register_user('Register user'):
            st.success('User registered successfully')
    except Exception as e:
        st.error(e)

    try:
        username_forgot_pw, email_forgot_password, random_password, submitted = authenticator.forgot_password('Forgot password')
        if username_forgot_pw:
            st.success('New password sent securely')
            
            # Random password to be transferred to user securely
            print("New password:", random_password)
            # Just an example

        elif submitted:
            st.error('Username not found')
    except Exception as e:
        st.error(e)

    try:
        username_forgot_username, email_forgot_username, submitted = authenticator.forgot_username('Forgot username')
        if username_forgot_username:
            st.success('Username sent securely')
            
            # Username to be transferred to user securely
            print("Username:", username_forgot_username)
            # Just an example

        elif submitted:
            st.error('Email not found')
    except Exception as e:
        st.error(e)
