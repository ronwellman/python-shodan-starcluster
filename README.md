# Python: Shodan Starcluster
![starcluster.gif](https://www.yoursecurity.tech/_assets/starcluster.gif)

Starcluster automates searching for vulnerable systems within the same postal code. It is written in Python 3 and relies on three, third-party libraries: the Shodan API, GuerrillaMail, and MechanicalSoup.

Shodan is the flare-gun of the script. With an API key & query statement, it searches its remote database of devices directly connected to the Internet. GuerrillaMail generates temporary e-mailboxes that expire after one hour (used to register for a Shodan account). MechanicalSoup is a combination of two other libraries: Mechanize and BeautifulSoup. The former interacts with web pages and submit forms while the latter parses HTML tags.

## Installation (Debian/Ubuntu)

Install Python 3 and the Python Package Installer (PIP)

```
sudo apt install python3 pip3
```

If pipenv is not installed

```
pip install --user pipenv
```

Initialize pipenv and install third-party libraries

```
pipenv --three
pipenv install shodan python-guerrillamail mechanicalsoup
```

Download script

```
git clone https://github.com/yoursecuritytech/python-shodan-starcluster.git
```

## Usage

Activate pipenv virtual environment in a new shell

```
pipenv shell
```

Run script with default arguments

```
/path/to/startcluster.py
```

Run script with custom arguments

```
/path/to/starcluster.py -a <API key> -p <postal code>
```

---

**Copyright**<br>
This project is licensed under the terms of the [MIT license](/LICENSE).
