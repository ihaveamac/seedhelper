import os,requests,os.path,cookielib,getpass,sys,signal,time,re

s = requests.Session()
baseurl = "https://seedhelper.figgyc.uk"
currentid = ""

username = raw_input("Username: ")
password = getpass.getpass("Password: ")
print("Logging in...")
r = s.post(baseurl + "/login", data={'username': username, 'password': password})
print(r.url)
if r.url == baseurl + '/home':
    print("Login successful")
else:
    print("Login fail")
    sys.exit(0)

def signal_handler(signal, frame):
        print('Exiting...')
        s.get(baseurl + "/movable/" + currentid + "/cancel")
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

# https://stackoverflow.com/a/16696317 thx
def download_file(url, local_filename):
    # NOTE the stream=True parameter
    r = requests.get(url, stream=True)
    with open(local_filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024):
            if chunk: # filter out keep-alive new chunks
                f.write(chunk)
                #f.flush() commented by recommendation from J.F.Sebastian
    return local_filename

while True:
    print("Finding work...")
    r = s.get(baseurl + "/work/movables")
    if r.url == baseurl + "/work":
        print("No work. Waiting 5 minutes...")
        time.sleep(300)
    else:
        regex = re.compile(r".*/work/movable/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
        currentid = regex.findall(r.url)[0]
        print("Downloading part1 for device " + currentid)
        download_file(baseurl + '/static/ugc/part1/' + currentid + '_part1.sed', 'movable_part1.sed')
        print("Bruteforcing")
        os.system(sys.executable + " seedminer_launcher.py gpu")
        if os.path.isfile("movable.sed"):
            print("Uploading")
            ur = s.post(r.headers['Location'], files={'file': open('movable.sed', 'rb')})
            if ur.headers['Location'] == '/work':
                print("Upload succeeded!")
                os.remove("movable.sed")
            else:
                print("Upload failed!")
                print(ur)
        else:
            print("Failed!")
            sys.exit(0)





