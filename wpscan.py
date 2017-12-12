import re
import os
import sys
import random
import json



class wpscan(object):
    def parser(self, rawfilename):
        #
        # Main Vuln
        #
        regex = r'(\[\d+m\[)([\+!i]+)(\].?\[0m Title: WordPress\s*)(\<\= )?([\d\.\-]+) \- (.+)([^[]*)((\[34m\[i].\[0m Fixed in: )([^[].*))?'
        rawfilestring = open(rawfilename).read()
        firstposition = ""
        lastposition = ""


        jsonstring = []
        alltext = {}


        matches = re.finditer(regex, rawfilestring)
        for (matchNum, match) in enumerate(matches):
            if matchNum == 0:
                firstposition = match.start()
            lastposition = match.end()
            singlevul = {}
            singlevul["vulnerability"] = match.group(6)
            singlevul["severity"] = match.group(2)
            if match.group(4) == None:
                singlevul["problem"] = match.group(5)
            else:
                singlevul["problem"] = "in less than " + match.group(5)
            references = match.group(7).split()
            refre = []
            count = 0
            for i in references:
                if i != "Reference:" and i != "\x1b":
                    refre.append(i)
            singlevul["reference"] = refre
            singlevul["fixed"] = match.group(10)
            jsonstring.append(singlevul)
            alltext["Body"] = jsonstring


        regexheder = r'(\[3(2|3)m\[(\+|!)].?\[0m )([^[]*)'

        # Header Vuln
        header = rawfilestring[:firstposition]
        footer = rawfilestring[lastposition:]
        matches = re.finditer(regexheder, header)
        head = []
        for (matchNum, match) in enumerate(matches):
            single = {}
            single["severity"] = match.group(3)
            single["detail"] = match.group(4)[:(match.group(4).find("\n\x1b"))]
            head.append(single)
        alltext["Header"] = head
        # jsonstring.append(head)

        # Footer Vuln
        matches = re.finditer(regexheder, footer)
        foot = []
        for (matchNum, match) in enumerate(matches):
            single = {}
            single["severity"] = match.group(3)
            single["detail"] = match.group(4)[:(match.group(4).find("\n\x1b")-1)]
            foot.append(single)
        alltext["Footer"] = foot
        # jsonstring.append(foot)
        #return parser result
        return alltext




if __name__ == '__main__':
    comingfrom = wpscan().parser(sys.argv[1])
    print json.dumps(comingfrom)
    # parser = WcscanParser(sys.argv[1])
    # for item in parser.items:
    #     if item.status == 'up':
    #         print item
