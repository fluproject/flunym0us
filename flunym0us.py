# Flunym0us is a tool of Flu Project (http://www.flu-project.com)
#
# Authors:
#	Juan Antonio Calles (@jantonioCalles)
#	Pablo Gonzalez (@fluproject)
#	Chema Garcia (@sch3m4)
#	German Sanchez (@enelpc)
# 
# Flunym0us is distributed under the terms of GPLv3 license
#
# ChangeLog 1.0:
#  [+] Search Wordpress Plugins
#  [+] Search Moodle Extensions
# ChangeLog 2.0:
#  [+] http user-agent hijacking
#  [+] http referer hijacking
#  [+] Search Wordpress Version
#  [+] Search Wordpress Latest Version
#  [+] Search Version of Wordpress Plugins
#  [+] Search Latest Version of Wordpress Plugins
#  [+] Search Path Disclosure Vulnerabilities
#  [+] Search Wordpress Authors
#
# This tool has been download from http://www.flu-project.com/downloadflu/flunym0us

import os
import sys
import signal
import urllib2
import httplib
import argparse
import threading
import multiprocessing

from useragents import getUserAgent

class MaxRetriesReached(Exception):

    def __init__(self,value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class URLRequest():
    """
    Class to do the HTTP/S requests
    """

    # host
    host = None
    # timeout
    TIMEOUT = 30
    # connection retries
    RETRIES = 10
    # body
    body = ''
    # final url
    url = ''
    
    def __init__(self, host = None, timeout = TIMEOUT, retries = RETRIES ):
        self.setHost(host)
        self.setTimeout(timeout)
        self.setRetries(retries)
    
    
    def setHost(self,host):
        self.host = host
    
    
    def setTimeout(self,timeout=TIMEOUT):
        self.TIMEOUT = timeout


    def setRetries(self,retries=RETRIES):
        self.RETRIES = retries
        
    
    def getBody(self):
        return self.body
    
    
    def getUrl(self):
        return self.url


    def doRequest(self,path=''):
        self.body = ''
        attempt = 0
        while attempt < self.RETRIES:
            try:
                # makes the request and stores the response
                req = urllib2.Request(self.host + path)
                req.add_header('User-agent', getUserAgent())
                req.add_header('Referer',self.host + path)
                response = urllib2.urlopen(req,timeout=self.TIMEOUT)
                self.url = response.geturl()
                self.body = response.read()
                response.close()
            except urllib2.URLError, e:
                if hasattr(e,'code') and e.code in [404,403,500]:
                    return e                
                
                attempt += 1
                print "[w] Retrying %s (%d/%d): %s" % (path, attempt, self.RETRIES ,str(e))
                continue
            
            except (httplib.InvalidURL,urllib2.HTTPError),e:
                return e
            
            except Exception,e:
                print "[w00t] GOT AN UNKNOWN ERROR: %s" % str(e)
                return e
        
            break
        
        ret = None
        # if attempts count is greater than retries, return error
        if not attempt < self.RETRIES:
            ret = MaxRetriesReached('Max retries (%d) reached, try to increase them ;-)' % self.RETRIES)
        
        return ret
    
    # search Path Disclosure
    def PathDisclosure(self, plugin):
        error = self.doRequest("/wp-content/plugins/"+plugin+"/"+plugin+".php")
        if error is not None:
            return None

        return ("[" + self.body.replace("<b>", '').replace("</b>", "").replace("<br />", "").strip("\n")+"]").strip()
        

class WPlugin():
    """
    Class to get the latest plugin version from Wordpress (official) site
    """
    
    # URL Request object
    request = None
    
    def __init__(self,timeout,retries):
        self.request = URLRequest('http://api.wordpress.org/plugins/info/1.0/' , timeout, retries)
    
    
    def getLatestVersion(self,plugin):
        error = self.request.doRequest(plugin + '.xml')
        if error is not None:
            return (False,error)
        
        content = self.request.getBody()
        
        if content.find('<NULL/>') > 0 or content.find('<version ') < 0:
            return (False,'Not an official plugin?')
        
        content = content[content.find('<version '):]
        content = content[content.find('CDATA['):]
        content = content[6:content.find(']')]
        
        return (True,content)


class Worker(multiprocessing.Process):
        
        parent = None
        queue = None
        engine = None
        path = None
        nthreads = None
        thlist = None
        # object to get the latest official version
        wplugin = None
        
        def __init__(self, parent, work_queue, threads):
            multiprocessing.Process.__init__(self)
            
            self.parent = parent
            self.queue = work_queue
            self.nthreads = threads
            self.thlist = []
            
            if self.parent.engine == 'wordpress':
                self.path = '/wp-content/plugins/'
            else:
                self.path = '/mod/'
            
        
        def threads(self):
            self.wplugin = WPlugin(self.parent.timeout,self.parent.retries)
            # creates the engine object
            self.engine = URLRequest(self.parent.host,self.parent.timeout,self.parent.retries)
            
            # while queue is not empty (there are more plugins to check) and user has not interrupted us
            while not self.parent.queue.empty() and not self.parent.finish.is_set():
                try:
                    # get a plugin
                    plugin = self.parent.queue.get_nowait()
                    # make the request
                    try:
                        error = self.engine.doRequest(self.path + plugin)
                    except Exception,e:
                        print "[FLUUU] I GOT AN UNHANDLED ERROR: %s" % str(e)
                        continue
                    except MaxRetriesReached,e:
                        print "[e] %s" % str(e)
                        continue
                    
                    # by default, found is set to false
                    found = False
                    if type(error) == urllib2.HTTPError:
                        if error.read().find('A required parameter (id) was missing') >= 0:
                            found = True  # plugin found
                        if error.code == 403:
                            found = True  # plugin found
                    
                    if found is True:
                        msg = "[i] Plugin found: %s" % plugin
                        # search PathDisclosure
                        if self.parent.engine == 'wordpress':
                            # path disclosure?
                            pd = self.engine.PathDisclosure(plugin)
                            if pd is not None:
                                msg += "\n\t- Path disclosure: %s" % pd
                            
                            # get the latest plugin version
                            gotit,data = self.wplugin.getLatestVersion(plugin)
                            if data is not None:
                                msg += "\n\t- Latest version: %s" % data
                            
                            # get the installed plugin version
                            error = self.engine.doRequest(self.path + plugin + '/readme.txt')
                            if error is None:
                                content = self.engine.getBody()
                                content = content[content.find('Stable tag:'):]
                                pversion = content[11:content.find('\n')].strip()
                                msg += '\n\t- Installed version: %s' % pversion
                                                                # needs to be upgraded
                                if data != pversion and gotit is True:
                                    msg += '\n\t- NEEDS TO BE UPGRADED!'
                            elif error.code == 404:
                                msg += '\n\t- Cannot get the installed version, you may want to check it manually'
                                
                            elif error.code != 404:
                                print "\n\tError: %s" % str(error)
                        
                        msg += '\n'
                        print msg
                    
                except multiprocessing.queues.Empty:
                    break

        def run(self):
            # let us to decide when to exit ;-)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            
            # launch the threads
            for i in range(0,self.nthreads):
                th = threading.Thread(target=self.threads)
                self.thlist.append(th)
                th.start()
            
            for th in self.thlist:
                th.join()

class Flunym0us():
            
    NPROCESS = multiprocessing.cpu_count()
    NTHREADS = 2
    
    # queue to write in the plugins names
    queue = None
    workers = []
    finish = None
    
    engine = None
    host = None
    wordlist = None
    timeout = None
    retries = None
    
    def __init__(self):
        self.finish = multiprocessing.Event()
        self.finish.clear()
    
    def __storeParams(self,args):
        """
        Store the parameters
        """
        self.engine = args.engine
        self.host = args.host
        self.wordlist = args.wordlist
        self.timeout = float(args.timeout)
        self.retries = int(args.retries)
        self.NPROCESS = int(args.process)
        self.NTHREADS = int(args.threads)
            
        
    # print Wordpress Version
    def WordpressVersion(self):
        
        print "[i] Installed Wordpress version:" ,
        sys.stdout.flush()
        
        req = URLRequest(self.host,self.timeout,self.retries)
        error = req.doRequest('/readme.html')
        if error is not None:
            print "%s" % str(error)
            return

        code = req.getBody()
        code=code[code.find("Version "):]
        version=code[len('Version '):code.find("<")].strip()
        
        if len(version) == 0:
            print "Invalid parsing??"
            return
        
        print version
        
        print "[i] Latest official release:",
        sys.stdout.flush()
        req.setHost('https://wordpress.org/download')
        error = req.doRequest('/')
        if error is not None:
            print "%s" % str(error)
        
        code = req.getBody()
        code = code[code.find('Download&nbsp;WordPress&nbsp;'):]
        code = code[len('Download&nbsp;WordPress&nbsp;'):code.find('<')]
        lversion = code.strip()
        print lversion
        
        if lversion != version:
            print "[W] Wordpress installation *OUTDATED!!*"
    

    # print Wordpress Authors
    def WordpressAuthors(self):
        print "\n[i] Registered Wordpress Authors:" 
        sys.stdout.flush()

        i = 0
        error = None
        req = URLRequest(self.host,self.timeout,self.retries)
        tmplogin = None
        old_author = None
        author = None
        login = None
        
        while error is None:
            i=i+1
            error = req.doRequest('/?author='+str(i))
            if error is not None:
                break
            code = req.getBody()
            code=code[code.find("<title>"):]
            
            old_author = author
            author=code[len('<title>'):code.find("</title>")].strip()
            if len(author) == 0:
                print "\t+ Invalid parsing??"
                return
            
            tmplogin = login
            furl = req.getUrl()
            if furl[-1:] != '/':
                login = os.path.basename(furl)
            else:
                login = os.path.basename(furl[:-1])
            
            if login.find('author=') > 0:
                msg = "\t- %s" % author
            else:
                msg = '\t- %s => %s' % (login,author)
            
            if login is not None:
                if tmplogin == login:
                    break
            elif old_author == author:
                break                
            
            print msg
    
    def __parseArgs(self):
        # specify what arguments do we accept
        parser = argparse.ArgumentParser()
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('-wp', '--wordpress', help='Scan WordPress site', dest='engine' ,  action='store_const', const='wordpress')
        group.add_argument('-mo', '--moodle', help='Scan Moodle site', dest='engine' ,  action='store_const', const='moodle')
        parser.add_argument('-H', '--host', metavar='HOST', help='Website to be scanned' )
        parser.add_argument('-w','--wordlist', metavar='WORDLIST', nargs=1, type=argparse.FileType('rt') , help='Path to the wordlist to use' , dest='wordlist', required=True)
        parser.add_argument('-t','--timeout' , default = URLRequest.TIMEOUT, help='Connection timeout' ,  required=False)
        parser.add_argument('-r','--retries' , default = URLRequest.RETRIES, help='Connection retries' , required=False)
        parser.add_argument('-p','--process', default = Flunym0us.NPROCESS, help='Number of process to use' , required=False)
        parser.add_argument('-T','--threads', default = Flunym0us.NTHREADS, help='Number of threads (per process) to use' , required=False)

        if len(sys.argv) > 1:
            args = parser.parse_args()
        else:
            parser.print_usage()
            return (None,False)
        
        self.__storeParams(args)
        
        return (args,True)

    def main(self):        
        args,ret = self.__parseArgs()
        if ret == False:
            return

        print "[i] Running %d parallel threads (%d %s with %d %s)\n" % (self.NPROCESS * self.NTHREADS , self.NPROCESS, "processes" if self.NPROCESS > 1 else "process" , self.NTHREADS , "threads" if self.NTHREADS > 1 else "thread")
        
        # search version
        try:
            if self.engine == 'wordpress':
                self.WordpressVersion()
                self.WordpressAuthors()
        except KeyboardInterrupt:
            return

        try:
            print "\n[i] Loading queue..." ,
            sys.stdout.flush()
            self.queue = multiprocessing.Queue()
            for tmp in args.wordlist[0].readlines():
                self.queue.put(tmp.strip())
            print "OK"
        except KeyboardInterrupt:
            while not self.queue.empty():    
                self.queue.get(block=False)
            return

        try:
            print "\n[i] Retrieving plugins list...\n"
            for i in range(self.NPROCESS):
                wk = Worker(self,self.queue,self.NTHREADS)
                wk.start()
                self.workers.append(wk)
                
            for wk in self.workers:
                wk.join()
                
        except KeyboardInterrupt:
            print "\n[i] Waiting for the threads to finish..."
            self.finish.set()
            # wait for workers
            for wk in self.workers:
                wk.join()
            # clear the queue
            while not self.queue.empty():    
                self.queue.get(block=False)


if __name__ == "__main__":
    print ' ____    ___                                           ____                    	  ___           __    	'
    print '/\  __\ /\_ \                                         / __ \                     /`___`\       /`__`\ 	'
    print '\ \ \__ \//\ \     __  __    ___   __  __    ___ ___ /\ \/\ \  __  __    ____   /\_\ /\ \     /\ \/\ \ 	'
    print ' \ \  _\  \ \ \   /\ \/\ \ /` _ `\/\ \/\ \ /` __` __`\ \ \ \ \/\ \/\ \  /  __\  \/_/// /__    \ \ \ \ \ 	'
    print '  \ \ \/   \_\ \_ \ \ \_\ \/\ \/\ \ \ \_\ \/\ \/\ \/\ \ \ \_\ \ \ \_\ \/\__   \    // /_\ \ __ \ \ \_\ \ 	'
    print '   \ \_\   /\____\ \ \____/\ \_\ \_\/`____ \ \_\ \_\ \_\ \____/\ \____/\/\____/   /\______//\_\ \ \____/	'
    print '    \/_/   \/____/  \/___/  \/_/\/_/`/___/> \/_/\/_/\/_/\/___/  \/___/  \/___/    \/_____/ \/_/  \/___/ 	'
    print '                                      /\___/                                    				'
    print '                                      \/__/    								'
    print ''
    print ' Flunym0us is a Vulnerability Scanner for Wordpress and Moodle. Created by http://www.flu-project.com\n'
    
    flu = Flunym0us()
    flu.main()
