import shlex
import subprocess
import functools

def get_whois_path():
    """
    Returns the location path where whois is installed
    by calling which whois
    """

    cmd = "which whois"
    args = shlex.split(cmd)
    sub_proc = subprocess.Popen(args, stdout=subprocess.PIPE)

    try:
        output, errs = sub_proc.communicate(timeout=15)
    except Exception as e:
        print(e)
        sub_proc.kill()
    else:
        return output.decode('utf8').strip()


def whois_is_installed():
    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(*args, **kwargs):
            whois_path = get_whois_path()
                
            if(os.path.exists(whois_path)):
                return await func(*args, **kwargs)
            else:
                print({"error":True, "msg":"whois has not been install on this system yet!"})
                return {"error":True, "msg":"whois has not been install on this system yet!"}
        return wrapped
    return  wrapper 
