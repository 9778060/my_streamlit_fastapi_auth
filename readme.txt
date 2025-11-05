INITIAL:
sudo apt-get update
sudo apt-get install libpython3-dev
sudo apt-get install python-pip
sudo pip install virtualenv
sudo apt-get install python3-venv

VENV:
CREATE - virtualenv -p python3 venv
ACTIVATE - source venv/bin/activate

PACKAGES:
pip install pyjwt
pip install bcrypt
pip install streamlit
pip install extra-streamlit-components
pip install psycopg2-binary
pip install fastapi
pip install pydantic
pip install "uvicorn[standard]"
pip install alembic
pip install slowapi

STREAMLIT:
streamlit run streamlit_test.py

FASTAPI:
uvicorn auth_api:app --reload
