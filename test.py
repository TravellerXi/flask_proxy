import requests

response = requests.post("http://localhost:5000/proxy", json={
    "url": "https://jsonplaceholder.typicode.com/posts",
    "method": "GET"
})
print(response.json())
