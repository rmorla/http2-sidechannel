# http2-sidechannel

Before running the HTTP/2 traffic analysis tool, ensure you have ``python3 >= 3.6``, ``pip3``, and ``tshark`` installed.

You can install the project dependencies by running the following command (only required once):

```
pip3 install -r requirements.txt
```

Then, to perform analysis against the provided sample .pcap file, execute the following command:

```
python3 main.py test/firefox-1.pcap
```

A directory called ``firefox-1`` should appear inside the ``test`` directory. Check if the output matches the files inside the ``test_output`` directory.

You can try yourself with your own .pcap files (for instance, ``mycapture.pcap``), as long as you supply the corresponding pre-master secrets inside ``mycapture.log``.
