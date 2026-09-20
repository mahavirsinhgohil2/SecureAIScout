import unittest

from demo_app.app import app


class ShopEasyTests(unittest.TestCase):
	def setUp(self):
		app.config.update(TESTING=True)
		self.client = app.test_client()

	def test_home_identifies_shopeasy(self):
		response = self.client.get("/")
		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.get_json()["name"], "ShopEasy")

	def test_login_route_exists(self):
		response = self.client.post("/login", data={})
		self.assertEqual(response.status_code, 400)

	def test_comment_route_exists(self):
		response = self.client.post("/comment", data={})
		self.assertEqual(response.status_code, 200)

	def test_hash_route_exists(self):
		response = self.client.post("/login", data={"username": "demo", "password": "demo"})
		self.assertEqual(response.status_code, 200)

	def test_get_table_rejects_unknown_table(self):
		response = self.client.get("/get-table?table=orders")
		self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
	unittest.main()
