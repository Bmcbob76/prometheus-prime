from starlette import status


def test_openapi(client):
    response = client.get("/openapi.json")
    print(response.json())
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["openapi"] == "3.1.0"
