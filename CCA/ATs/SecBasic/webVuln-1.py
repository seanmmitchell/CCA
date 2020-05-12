standardEnabled=False
secureEnabled=False

if "server" in matches:
    standardEnabled = True
elif "secure-server" in matches:
    secureEnabled = True

if standardEnabled:
    Out(OutSev.Warning, "The HTTP server is enabled on the device.")
if secureEnabled:
    Out(OutSev.Warning, "The HTTPS server is enabled on the device.")