# DNS Client
 ECSE 316 - Signal and network Projects
### Setup
Make sure that Python 3.9 or later is installed on your system.

### Usage
Some examples on how to use the program.

```
python3 DnsClient.py @8.8.8.8 www.google.com
```

```
python3 DnsClient.py @8.8.8.8 mcgill.ca
```

```
python3 DnsClient.py -t 5 -r 3 @8.8.8.8 www.amazon.com
```

```
python3 DnsClient.py @8.8.8.8 www.netflix.com -mx
```

```
python3 DnsClient.py -t 5 -r 3 @8.8.8.8 www.Github.com -ns
```