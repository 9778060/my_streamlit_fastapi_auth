import jwt
import streamlit as st
from datetime import datetime, timedelta
import extra_streamlit_components as stx
import json
import requests

from .exceptions import CredentialsError, ResetError, RegisterError, ForgotError, UpdateError


def init_authentication():

    authenticator = Authenticate(
        **st.secrets["cookies"]
    )

    return authenticator


class Authenticate:
    """
    This class will create login, logout, register user, reset password, forgot password, 
    forgot username, and modify user details widgets.
    """
    def __init__(self, cookie_name: str, key: str, cookie_expiry_days: int=30):
        """
        Create a new instance of "Authenticate".

        Parameters
        ----------
        cookie_name: str
            The name of the JWT cookie stored on the client's browser for passwordless reauthentication.
        key: str
            The key to be used for hashing the signature of the JWT cookie.
        cookie_expiry_days: int
            The number of days before the cookie expires on the client's browser.
        """
        self.cookie_name = cookie_name
        self.key = key
        self.cookie_expiry_days = cookie_expiry_days
        self.cookie_manager = stx.CookieManager()

        if 'name' not in st.session_state:
            st.session_state['name'] = None
        if 'authentication_status' not in st.session_state:
            st.session_state['authentication_status'] = None
        if 'username' not in st.session_state:
            st.session_state['username'] = None
        if 'logout' not in st.session_state:
            st.session_state['logout'] = None


    def _token_encode(self) -> str:
        """
        Encodes the contents of the reauthentication cookie.

        Returns
        -------
        str
            The JWT cookie for passwordless reauthentication.
        """
        return jwt.encode({'name':st.session_state['name'],
            'username':st.session_state['username'],
            'exp_date':self.exp_date}, self.key, algorithm='HS256')

    def _token_decode(self) -> str:
        """
        Decodes the contents of the reauthentication cookie.

        Returns
        -------
        str
            The decoded JWT cookie for passwordless reauthentication.
        """
        try:
            return jwt.decode(self.token, self.key, algorithms=['HS256'])
        except:
            return False

    def _set_exp_date(self) -> str:
        """
        Creates the reauthentication cookie's expiry date.

        Returns
        -------
        str
            The JWT cookie's expiry timestamp in Unix epoch.
        """
        return (datetime.utcnow() + timedelta(days=self.cookie_expiry_days)).timestamp()

    def _check_pw(self) -> bool:
        """
        Checks the validity of the entered password.

        Returns
        -------
        bool
            The validity of the entered password by comparing it to the hashed password on disk.
        """

        inputs = {"username": self.username, "password": self.password}
        res = requests.post(url=f"{st.secrets['fastapi']['home_path']}/check_password", data=json.dumps(inputs))
        
        if res.status_code == 200:
            return True
        elif res.status_code == 429:
            raise CredentialsError("Too many requests")
        else:
            return False

        # FastAPI


    def _check_cookie(self):
        """
        Checks the validity of the reauthentication cookie.
        """
        self.token = self.cookie_manager.get(self.cookie_name)
        if self.token is not None:
            self.token = self._token_decode()
            if self.token is not False:
                if not st.session_state['logout']:
                    if self.token['exp_date'] > datetime.utcnow().timestamp():
                        if 'name' and 'username' in self.token:
                            st.session_state['name'] = self.token['name']
                            st.session_state['username'] = self.token['username']
                            st.session_state['authentication_status'] = True
    
    def _check_credentials(self, inplace: bool=True) -> bool:
        """
        Checks the validity of the entered credentials.

        Parameters
        ----------
        inplace: bool
            Inplace setting, True: authentication status will be stored in session state, 
            False: authentication status will be returned as bool.
        Returns
        -------
        bool
            Validity of entered credentials.
        """

        inputs = {"username": self.username}
        res = requests.post(url=f"{st.secrets['fastapi']['home_path']}/check_credentials", data=json.dumps(inputs))
        
        if res.status_code == 200:
            response_json = json.loads(res.content.decode('utf-8'))
        elif res.status_code == 429:
            raise CredentialsError("Too many requests")
        else:
            return False

        # FastAPI

        user_found = response_json["username"]
        name_found = response_json["name"]

        if self.username == user_found:
            try:
                if self._check_pw():
                    if inplace:
                        st.session_state['name'] = name_found
                        self.exp_date = self._set_exp_date()
                        self.token = self._token_encode()
                        self.cookie_manager.set(self.cookie_name, self.token,
                            expires_at=datetime.now() + timedelta(days=self.cookie_expiry_days))
                        st.session_state['authentication_status'] = True
                    else:
                        return True
                else:
                    if inplace:
                        st.session_state['authentication_status'] = False
                    else:
                        return False
            except Exception as e:
                print(e)
        else:
            if inplace:
                st.session_state['authentication_status'] = False
            else:
                return False

        return True

    def login(self, form_name: str, location: str='main') -> tuple:
        """
        Creates a login widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the login form.
        location: str
            The location of the login form i.e. main or sidebar.
        Returns
        -------
        str
            Name of the authenticated user.
        bool
            The status of authentication, None: no credentials entered, 
            False: incorrect credentials, True: correct credentials.
        str
            Username of the authenticated user.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if not st.session_state['authentication_status']:
            self._check_cookie()
            if st.session_state['authentication_status'] != True:
                if location == 'main':
                    login_form = st.form('Login')
                elif location == 'sidebar':
                    login_form = st.sidebar.form('Login')

                login_form.subheader(form_name)
                self.username = login_form.text_input('Username').lower()
                st.session_state['username'] = self.username
                self.password = login_form.text_input('Password', type='password')

                if login_form.form_submit_button('Login'):
                    if not self._check_credentials():
                        raise CredentialsError

        return st.session_state['name'], st.session_state['authentication_status'], st.session_state['username']

    def logout(self, button_name: str, location: str='main'):
        """
        Creates a logout button.

        Parameters
        ----------
        button_name: str
            The rendered name of the logout button.
        location: str
            The location of the logout button i.e. main or sidebar.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            if st.button(button_name):
                self.cookie_manager.delete(self.cookie_name)
                st.session_state['logout'] = True
                st.session_state['name'] = None
                st.session_state['username'] = None
                st.session_state['authentication_status'] = None
        elif location == 'sidebar':
            if st.sidebar.button(button_name):
                self.cookie_manager.delete(self.cookie_name)
                st.session_state['logout'] = True
                st.session_state['name'] = None
                st.session_state['username'] = None
                st.session_state['authentication_status'] = None

    def _update_password(self, username: str, password: str):
        """
        Updates credentials dictionary with user's reset hashed password.

        Parameters
        ----------
        username: str
            The username of the user to update the password for.
        password: str
            The updated plain text password.
        """

        inputs = {"username": username, "password": password}
        res = requests.post(url=f"{st.secrets['fastapi']['home_path']}/reset_password", data=json.dumps(inputs))
        
        if res.status_code == 200:
            return True
        elif res.status_code == 429:
            raise ResetError("Too many requests")
        else:
            return False

        # FastAPI



    def reset_password(self, username: str, form_name: str, location: str='main') -> bool:
        """
        Creates a password reset widget.

        Parameters
        ----------
        username: str
            The username of the user to reset the password for.
        form_name: str
            The rendered name of the password reset form.
        location: str
            The location of the password reset form i.e. main or sidebar.
        Returns
        -------
        str
            The status of resetting the password.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            reset_password_form = st.form('Reset password', clear_on_submit=True)
        elif location == 'sidebar':
            reset_password_form = st.sidebar.form('Reset password', clear_on_submit=True)
        
        reset_password_form.subheader(form_name)
        self.username = username.lower()
        self.password = reset_password_form.text_input('Current password', type='password')
        new_password = reset_password_form.text_input('New password', type='password')
        new_password_repeat = reset_password_form.text_input('Repeat password', type='password')

        if reset_password_form.form_submit_button('Reset'):
            if self._check_credentials(inplace=False):
                if len(new_password) > 0:
                    if new_password == new_password_repeat:
                        if self.password != new_password: 
                            if self._update_password(self.username, new_password):
                                return True
                            else:
                                raise ResetError('Error by reseting the password')    
                        else:
                            raise ResetError('New and current passwords are the same')
                    else:
                        raise ResetError('Passwords do not match')
                else:
                    raise ResetError('No new password provided')
            else:
                raise CredentialsError
    

    def register_user(self, form_name: str, location: str='main') -> bool:
        """
        Creates a password reset widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the password reset form.
        location: str
            The location of the password reset form i.e. main or sidebar.
        Returns
        -------
        bool
            The status of registering the new user, True: user registered successfully.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            register_user_form = st.form('Register user', clear_on_submit=True)
        elif location == 'sidebar':
            register_user_form = st.sidebar.form('Register user', clear_on_submit=True)

        register_user_form.subheader(form_name)
        new_email = register_user_form.text_input('Email')
        new_username = register_user_form.text_input('Username').lower()
        new_name = register_user_form.text_input('Name')
        new_password = register_user_form.text_input('Password', type='password')
        new_password_repeat = register_user_form.text_input('Repeat password', type='password')

        if register_user_form.form_submit_button('Register'):
            if len(new_email) and len(new_username) and len(new_name) and len(new_password) > 0:
                if new_password == new_password_repeat:
                    # FastAPI

                    inputs = {"username": new_username, "password": new_password, "email": new_email, "name": new_name}
                    res = requests.post(url=f"{st.secrets['fastapi']['home_path']}/register", data=json.dumps(inputs))
                    
                    if res.status_code == 200:
                        return True
                    elif res.status_code == 429:
                        raise RegisterError("Too many requests")
                    else:
                        response_json = json.loads(res.content.decode('utf-8'))
                        raise RegisterError(response_json["message"])
                else:
                    raise RegisterError('Passwords do not match')

            else:
                raise RegisterError('Please enter an email, username, name, and password')


    def forgot_password(self, form_name: str, location: str='main') -> tuple:
        """
        Creates a forgot password widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the forgot password form.
        location: str
            The location of the forgot password form i.e. main or sidebar.
        Returns
        -------
        str
            Username associated with forgotten password.
        str
            Email associated with forgotten password.
        str
            New plain text password that should be transferred to user securely.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            forgot_password_form = st.form('Forgot password', clear_on_submit=True)
        elif location == 'sidebar':
            forgot_password_form = st.sidebar.form('Forgot password', clear_on_submit=True)

        forgot_password_form.subheader(form_name)
        username = forgot_password_form.text_input('Username').lower()

        if forgot_password_form.form_submit_button('Submit'):
            if len(username) > 0:

                # FastAPI

                inputs = {"username": username}
                res = requests.post(url=f"{st.secrets['fastapi']['home_path']}/forgot_password", data=json.dumps(inputs))
                
                if res.status_code == 200:
                    response_json = json.loads(res.content.decode('utf-8'))
                    
                    username = response_json["username"]
                    email_found = response_json["email"]
                    new_password = response_json["password"]

                    return username, email_found, new_password, True
                elif res.status_code == 429:
                    raise ForgotError("Too many requests")
                else:
                    return False, None, None, True
            else:
                raise ForgotError('Username not provided')

        return None, None, None, False



    def forgot_username(self, form_name: str, location: str='main') -> tuple:
        """
        Creates a forgot username widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the forgot username form.
        location: str
            The location of the forgot username form i.e. main or sidebar.
        Returns
        -------
        str
            Forgotten username that should be transferred to user securely.
        str
            Email associated with forgotten username.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            forgot_username_form = st.form('Forgot username', clear_on_submit=True)
        elif location == 'sidebar':
            forgot_username_form = st.sidebar.form('Forgot username', clear_on_submit=True)

        forgot_username_form.subheader(form_name)
        email = forgot_username_form.text_input('Email')

        if forgot_username_form.form_submit_button('Submit'):
            if len(email) > 0:

                # FastAPI
                inputs = {"email": email}
                res = requests.post(url=f"{st.secrets['fastapi']['home_path']}/forgot_username", data=json.dumps(inputs))

                if res.status_code == 200:
                    response_json = json.loads(res.content.decode('utf-8'))
                    
                    username = response_json["username"]
                    email_found = response_json["email"]

                    return username, email_found, True
                elif res.status_code == 429:
                    raise ForgotError("Too many requests")
                else:
                    return None, None, True

            else:
                raise ForgotError('Email not provided')

        return None, email, False


    def update_user_details(self, username: str, form_name: str, location: str='main') -> bool:
        """
        Creates a update user details widget.

        Parameters
        ----------
        username: str
            The username of the user to update user details for.
        form_name: str
            The rendered name of the update user details form.
        location: str
            The location of the update user details form i.e. main or sidebar.
        Returns
        -------
        str
            The status of updating user details.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            update_user_details_form = st.form('Update user details', clear_on_submit=True)
        elif location == 'sidebar':
            update_user_details_form = st.sidebar.form('Update user details', clear_on_submit=True)
        
        update_user_details_form.subheader(form_name)
        self.username = username.lower()
        field = update_user_details_form.selectbox('Field', ['Name', 'Email']).lower()
        new_value = update_user_details_form.text_input('New value')

        if update_user_details_form.form_submit_button('Update'):
            if len(new_value) > 0:

                # FastAPI
                
                inputs = {"username": self.username, "field": field, "value": new_value}
                res = requests.post(url=f"{st.secrets['fastapi']['home_path']}/update_details", data=json.dumps(inputs))
                
                if res.status_code == 200:
                    if field == 'name':
                        st.session_state['name'] = new_value
                        self.exp_date = self._set_exp_date()
                        self.token = self._token_encode()
                        self.cookie_manager.set(self.cookie_name, self.token,
                        expires_at=datetime.now() + timedelta(days=self.cookie_expiry_days))
                    return True
                elif res.status_code == 429:
                    raise UpdateError("Too many requests")
                else:
                    response_json = json.loads(res.content.decode('utf-8'))
                    raise UpdateError(response_json["message"])

            if len(new_value) == 0:
                raise UpdateError('New value not provided')
