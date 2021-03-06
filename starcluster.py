#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
'''
Automates searching Shodan for vulnerable systems within the same postal code.
'''

# dunders
__author__ = 'Victor Fernandez III'
__version__ = '0.2.0'

# built-in libraries
import argparse
import datetime
import glob
import itertools
import logging
import string
import sys
import time
import random

# third-party libraries
import guerrillamail
import mechanicalsoup
import shodan


class Shodan():
    '''
    class for handling the registration and retrieval of a SHODAN API key
    '''
    shodanHomePage = 'https://www.shodan.io'
    shodanLoginPage = 'https://account.shodan.io/login'
    shodanRegistrationPage = 'https://account.shodan.io/register'

    def __init__(self, shodanAPIkey=None, username=None, email=None,
                 password=None, log=None, browser=None):
        self.shodanAPIkey = shodanAPIkey
        self.username = username
        self.email = email
        self.password = password
        self.gm = None
        self.log = log
        self.browser = browser

        if not self.log:
            self.log = print

        if not self.browser:
            browser = mechanicalsoup.StatefulBrowser(
                soup_config={'features': 'lxml'},
                raise_on_404=True,
                user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/65.0.3325.146 Safari/537.36')

        if self.shodanAPIkey is None:
            self.getShodanAPIkey()

        if self.shodanAPIkey is None:
            raise AssertionError('[!] Unable to attain an API key.')

    def __str__(self):
        '''
        return main Shodan parameters as a string
        '''
        return 'API Key: {} Username: {} Email: {} Password: {}'.format(
            self.shodanAPIkey, self.username, self.email, self.password)

    def checkForExistingKey(self):
        '''
        check local log for existing Shodan API key
        '''
        key = 'Using Shodan API key'

        for file in glob.glob('./*.log'):
            with open(file) as logFile:
                for logEntry in logFile:
                    if key in logEntry:
                        self.shodanAPIkey = logEntry.rstrip()[50:]
                        if len(self.shodanAPIkey) == 32:
                            return

    def generateEmail(self):
        '''
        generate email for Shodan account
        '''

        try:
            self.gm = guerrillamail.GuerrillaMailSession()
            self.email = self.gm.get_session_state()['email_address']
            self.username = self.email[:-23]
        except guerrillamail.GuerrillaMailException:
            self.log('[!] The GuerrillaMail API might be down...')

    def generatePassword(self):
        '''
        generate password for Shodan account
        '''
        characters = string.ascii_letters + string.digits + '!@#$%^&*()?'
        self.password = ''.join(random.sample(characters, 15))

    def registerWithShodan(self):
        '''
        register for a Shodan account
        '''
        if not self.email or not self.username:
            self.generateEmail()

        if not self.email:
            return

        self.generatePassword()

        self.log('[*] Registering with Shodan using the following credentials:')
        self.log(' +   Email address: ' + self.email)
        self.log(' +   Username: ' + self.username)
        self.log(' +   Password: ' + self.password)
        self.browser.open(self.shodanRegistrationPage)
        self.browser.select_form()
        self.browser['username'] = self.username
        self.browser['password'] = self.password
        self.browser['password_confirm'] = self.password
        self.browser['email'] = self.email
        self.browser.submit_selected()

    def activateShodanAccount(self):
        '''
        activate Shodan account using emailed URL
        '''
        spinner = itertools.cycle(['|', '/', '-', '\\', '|'])
        self.log('[*] Waiting for confirmation email from Shodan. Standby...')
        maxWaitTime = 120
        startTime = time.time()
        while (len(self.gm.get_email_list()) != 2):
            for i in range(1, 10):
                sys.stdout.write(' '+next(spinner)+' ')
                sys.stdout.flush()
                sys.stdout.write('\b\b\b')
                time.sleep(.5)
            if (len(self.gm.get_email_list()) == 2):
                sys.stdout.flush()
                self.log(' +   Email received.')
                break
            if time.time() > startTime + maxWaitTime:
                sys.stdout.flush()
                self.log('[!] Max wait time exceeded. Exiting...')
                exit()

        msg = self.gm.get_email((self.gm.get_email_list()[0].guid)).body
        soup = mechanicalsoup.form.BeautifulSoup
        activationURL = soup(msg, 'html.parser').find_all('a')[0].string
        self.browser.open(activationURL)

    def getShodanAPIkey(self):
        '''
        get API key from Shodan account if none found in local log
        '''
        self.checkForExistingKey()

        if self.shodanAPIkey:
            self.log('[+] Using Shodan API key: ' + self.shodanAPIkey)
        else:
            self.registerWithShodan()

            # ensure requisite SHODAN parameters were generated
            if not self.email or not self.username or not self.password:
                return

            self.activateShodanAccount()

            self.browser.open(self.shodanLoginPage)
            self.browser.select_form("form[action='/login']")
            self.browser['username'] = self.username
            self.browser['password'] = self.password
            self.browser['continue'] = self.shodanHomePage
            self.browser.submit_selected()

            self.log('[*] Retrieving key...')
            self.shodanAPIkey = self.browser.get_current_page().find_all(
                'li', {'id': 'api-key-content'})[0].string[9:]
            self.log('[+] Using Shodan API key: ' + self.shodanAPIkey)

    def searchPostalCode(self, postalCode):
        '''
        use Shodan API to search for publicly-accessible devices
        '''
        try:
            shodanAPI = shodan.Shodan(self.shodanAPIkey)
            neighborhood = shodanAPI.search(postalCode)
        except shodan.exception.APIError as error:
            self.log('[!] Shodan search failed: ' + str(error))
            return

        for neighbor in neighborhood['matches']:
            neighborIP = str(neighbor['ip_str'])
            neighborPort = str(neighbor['port'])
            self.log(' +   Neighbor: '+neighborIP+':'+neighborPort)
        self.log('[!] Done.')


def findNeighborhood(browser):
    '''
    find neighborhood using online service
    '''
    keyCDN = 'https://tools.keycdn.com/geo'
    browser.open(keyCDN)
    return browser.get_current_page().find_all('td')[12].string


def main():
    '''
    main script function
    '''
    # script arguments
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-a', help='Shodan API key')
    parser.add_argument('-p', help='postal code')
    args = parser.parse_args()
    postalCode = args.p

    # main logging parameters
    logging.basicConfig(
        filename=datetime.date.today().isoformat()+'_starcluster.log',
        level=logging.INFO,
        format='%(asctime)s:%(message)s'
        )
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    log = logger.info

    browser = mechanicalsoup.StatefulBrowser(
        soup_config={'features': 'lxml'},
        raise_on_404=True,
        user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/65.0.3325.146 Safari/537.36')

    # create Shodan object
    try:
        myShodan = Shodan(shodanAPIkey=args.a, log=log, browser=browser)
    except AssertionError as e:
        log(e)
        exit(1)

    if not postalCode:
        postalCode = findNeighborhood(browser)

    log('[+] Using Shodan API key: ' + myShodan.shodanAPIkey)
    log('[*] Launching digital star-cluster over: ' + postalCode)

    myShodan.searchPostalCode(postalCode)


if __name__ == '__main__':
    main()
