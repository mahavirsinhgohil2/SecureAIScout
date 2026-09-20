import hashlib
import os
import pickle
import sqlite3

from flask import Flask, abort, jsonify, request, render_template_string


app = Flask("ShopEasy")
secret_key = "shopeasy-local-demo-secret"
app.config["SECRET_KEY"] = secret_key

PRODUCTS = {
	"1": {"name": "Canvas Tote", "price": 18.0},
	"2": {"name": "Steel Bottle", "price": 24.0},
}
TABLES = {"products": PRODUCTS}


@app.get("/")
def home():
	return jsonify(name="ShopEasy", status="local demo")


@app.post("/login")
def login():
	username = request.form.get("username", "")
	password = request.form.get("password", "")
	if not username or not password:
		return jsonify(error="username and password are required"), 400

	password_hash = hashlib.md5(password.encode()).hexdigest()
	connection = sqlite3.connect(":memory:")
	connection.execute("CREATE TABLE users (username TEXT, password_hash TEXT)")
	connection.execute("INSERT INTO users VALUES ('demo', 'unused')")
	query = f"SELECT username FROM users WHERE username = '{username}' AND password_hash = '{password_hash}'"
	row = connection.execute(query).fetchone()
	connection.close()
	return jsonify(authenticated=bool(row))


@app.get("/ping")
def ping():
	host = request.args.get("host", "")
	if not host:
		return jsonify(error="host is required"), 400
	os.system(f"ping {host}")
	return jsonify(host=host, status="sent")


@app.post("/comment")
def comment():
	text = request.form.get("text", "")
	return render_template_string(f"<h1>ShopEasy comment</h1><p>{text}</p>")


@app.get("/product/<product_id>")
def product(product_id):
	if product_id not in PRODUCTS:
		abort(404)
	return jsonify(PRODUCTS[product_id])


@app.get("/get-table")
def get_table():
	table_name = request.args.get("table", "")
	if table_name not in TABLES:
		return jsonify(error="choose a supported table"), 400
	connection = sqlite3.connect(":memory:")
	connection.execute("CREATE TABLE products (id TEXT, name TEXT, price REAL)")
	for product_id, item in PRODUCTS.items():
		connection.execute("INSERT INTO products VALUES (?, ?, ?)", (product_id, item["name"], item["price"]))
	rows = connection.execute(f"SELECT id, name, price FROM {table_name}").fetchall()
	connection.close()
	return jsonify(rows=rows)


@app.post("/import-profile")
def import_profile():
	payload = request.get_data()
	if not payload:
		return jsonify(error="profile data is required"), 400
	profile = pickle.loads(payload)
	return jsonify(profile=profile)


if __name__ == "__main__":
	app.run(host="127.0.0.1", port=5000, debug=False)
