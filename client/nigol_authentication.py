"""
This module provides an authentication class, Authenticator, for handling JWT-based
authentication in Streamlit applications using API calls.
"""
import os
from datetime import timedelta, datetime
from typing import Optional

import extra_streamlit_components as stx
import jwt
import streamlit as st
import streamlit.components.v1 as components
from dotenv import load_dotenv

from jwt_utils import extract_claims_jwt
load_dotenv()


# Secret key for JWT encoding/decoding
SECRET_KEY = os.environ['JWT_SECRET_KEY']


class NigolAuthenticator:
    def __init__(self,
                 token_key: str = "access",
                 cookie_lifetime: timedelta = timedelta(days=7)
                 ):
        """
        Initializes the Authenticator instance with the specified parameters.
        """
        self.token_key = token_key
        self.cookie_lifetime = cookie_lifetime

        self.cookie_manager = stx.CookieManager()
        setup_session_keys()

    def _set_error(self, message):
        """
        Internal method to set an authentication error message.

        Parameters:
        - message (str): The error message to log.
        """
        st.error(message)

    def _check_cookie(self):
        """
        Internal method to check the authentication status based on the stored cookie.

        Returns:
        bool: True if the user is authenticated, False otherwise.
        """
        cookie_access_token = self.cookie_manager.get(self.token_key)
        if not cookie_access_token:
            st.session_state['authentication_status'] = False
            return False

        is_valid, message = verify_access_token(self.cookie_manager.get(self.token_key))
        if is_valid:
            st.session_state['authentication_status'] = True
            return True

        st.session_state['authentication_status'] = False
        self._set_error(message)
        return False

    def _check_external_jwt(self, external_jwt):
        if not external_jwt:
            self._set_error("Missing external JWT")
            return False

        try:
            claims = extract_claims_jwt(external_jwt)
            user_email = claims['email']
            access_token = create_access_token(identity=user_email)
            self.cookie_manager.set(self.token_key, access_token,
                                    expires_at=datetime.now() + self.cookie_lifetime)
            st.session_state['authentication_status'] = True

            return True
        except Exception as e:
            self._set_error(f"Bad external JWT: {e}")

            return False

    def _implement_logout(self):
        """
        Internal method to implement logout functionality by clearing cookies and session state.
        """
        self.cookie_manager.delete(self.token_key)

        st.session_state['authentication_status'] = None

    def login(self):
        if "authentication_status" not in st.session_state:
            st.session_state["authentication_status"] = None

        if not st.session_state['authentication_status']:
            self._check_cookie()
            if not st.session_state['authentication_status']:
                iframe_content = """
                <script>
                function onLoginClick() {
                    const modalWidth = Math.min(599, window.screen.width - 20),
                        modalHeight = Math.min(600, window.screen.height - 30);
                    const windowFeatures = `toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=yes,resizable=yes,copyhistory=no,width=${modalWidth},height=${modalHeight},top=${
            (window.screen.height - modalHeight) / 2
          },left=${(window.screen.width - modalWidth) / 2}`;
                    const originUrl = btoa(encodeURIComponent(window.parent.location.href));
                    window.open(
                        `https://nigol.ouihelp.fr?originUrl=${originUrl}`,
                        "LOGIN_WINDOW",
                        windowFeatures
                    );
                }
                
                function listener(e) {
                    var external_jwt = e.data.NIGOL_GOOGLE_JWT;
                    // Log the JWT to the console
                    console.log("JWT token à copier: ", external_jwt);
                    document.getElementById("external_jwt").innerText = external_jwt;
                };
        
                window.addEventListener("message", listener);
                </script>
                <p>
                    <button onclick="onLoginClick()">1/ Cliquer pour se connecter avec Nigol</button>
                </p>
                <div style="color: black; background-color: white;">
                    <h5>2/ Copier le JWT token qui va apparaître ci-dessous</h5>
                    <pre id="external_jwt"></pre>
                </div>
                """

                st.markdown("""
                # Un login en quatre étapes
                
                Désolé pour ce login un peu complexe, il faudra créer un custom 
                component Streamlit pour simplifier le processus.
                """)
                components.html(iframe_content)

                login_form = st.form('JWTLogin')
                external_jwt = login_form.text_input("3/ Coller le token JWT ici",
                                                     help="Enter the JWT from Nigol")

                # Retrieve and display the message
                if login_form.form_submit_button("4/ Login"):
                    self._check_external_jwt(external_jwt)

        return st.session_state['authentication_status']

    def logout(
            self,
            location: str = 'main',
            button_name: str = 'Logout',
            key: Optional[str] = None
    ):
        """
        Method to handle user logout form.

        Parameters:
        - location (str, optional): Location to display the logout button,
            either 'main' or 'sidebar'. Defaults to 'main'.
        - button_name (str, optional): The label for the logout button.
            Defaults to 'Logout'.
        - key (str, optional): A key to associate with the logout button for Streamlit.
            Defaults to None.

        Usage:
        ```
        authenticator = Authenticator(...)
        authenticator.login()

        if st.session_state["authentication_status"]:
            authenticator.logout()
        """
        if location == 'main':
            if st.button(button_name, key):
                self._implement_logout()
        elif location == 'sidebar':
            if st.sidebar.button(button_name, key):
                self._implement_logout()


def setup_session_keys():
    """
    Sets up default session keys in Streamlit session_state.

    This function initializes default session keys, such as "username" and
    "authentication_status", in Streamlit's session_state. These keys are
    used to store and retrieve information about the user's authentication status.

    """
    keys = ["authentication_status"]
    for key in keys:
        if key not in st.session_state:
            st.session_state[key] = None


# Simulated function to create JWT
def create_access_token(identity):
    expiration = datetime.utcnow() + timedelta(hours=1)
    return jwt.encode({'email': identity, 'exp': expiration}, SECRET_KEY, algorithm="HS256")


def verify_access_token(token):
    try:
        # Decode the token
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        # Check if the token has expired
        expiration = decoded.get('exp')
        if expiration is None:
            return False, "Token does not have an expiration date"
        # Convert expiration time to datetime object
        expiration_time = datetime.utcfromtimestamp(expiration)
        if expiration_time < datetime.utcnow():
            return False, "Token has expired"
        # Token is valid
        return True, decoded
    except jwt.ExpiredSignatureError:
        return False, "Token has expired"
    except jwt.InvalidTokenError:
        return False, "Invalid token"


nigol_authenticator = NigolAuthenticator()
