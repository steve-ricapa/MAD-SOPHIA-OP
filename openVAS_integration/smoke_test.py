from gvm_client import GVMClient
import os

with GVMClient(
    host="127.0.0.1",
    port=9390,
    user=os.getenv("GVM_USERNAME",""),
    password=os.getenv("GVM_PASSWORD",""),
    socket_path=os.getenv("GVM_SOCKET",""),
) as c:
    xml = c.get_tasks()
    print(xml[:500])
    print("...OK tasks")
