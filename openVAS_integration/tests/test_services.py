from services import map_status

def test_status():
    assert map_status("Running") == "running"
    assert map_status("Pending") == "pending"
    assert map_status("Completed") == "completed"
