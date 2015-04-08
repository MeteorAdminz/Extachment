'''
The MIT License (MIT)

Copyright (c) 2014 Patrick Olsen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Author: Patrick Olsen
Email: patrick.olsen@sysforensics.org
Twitter: @patrickrolsen
Version 0.1
'''
import os, re
import email
import argparse

def extractAttachment(msg, file_names, output_path):
    
    if len(msg.get_payload()) > 2:
        if isinstance(msg.get_payload(), str):
            print 'Could not process %s. Try manual extraction.' % (file_names)
            print '\tHeader of file: %s\n' % (msg.get_payload()[:8])
        
        elif isinstance(msg.get_payload(), list):
            #try:
            count = 0
            while count < len(msg.get_payload()):
                payload = msg.get_payload()[count]
                filename = payload.get_filename()
                if filename is not None:
                    magic = payload.get_payload(decode=True)[:4]
                    # Print the magic deader and the filename for reference.
                    printIT(file_names, magic, filename)
                    # Write the payload out.
                    writeFile(filename, payload, output_path)
                count += 1

    elif len(msg.get_payload()) == 2:
        payload = msg.get_payload()[1]
        filename = payload.get_filename()
        magic = payload.get_payload(decode=True)[:4]
        # Print the magic deader and the filename for reference.
        printIT(file_names, magic, filename)
        # Write the payload out.
        writeFile(filename, payload, output_path)        

    elif len(msg.get_payload()) == 1:
        attachment = msg.get_payload()[0]
        payload = attachment.get_payload()[1]
        filename = attachment.get_payload()[1].get_filename()
        magic = payload.get_payload(decode=True)[:4]
        # Print the magic deader and the filename for reference.
        printIT(file_names, magic, filename)
        # Write the payload out.
        writeFile(filename, payload, output_path)
    else:
        print 'Could not process %s\t%s' % (file_names, len(msg.get_payload()))  

def printIT(file_names, magic, filename):
    print 'Email Name: %s\n\tMagic: %s\n\tSaved File as: %s\n' % (file_names, magic, filename)
    
def writeFile(filename, payload, output_path):
    open(os.path.join(output_path + filename), 'wb').write(payload.get_payload(decode=True))
    
def main():
    parser = argparse.ArgumentParser(description='Attempt to parse the attachment from EML messages.')
    parser.add_argument('-p', '--path', help='Path to EML files.')
    parser.add_argument('-o', '--out', help='Path to write attachments to.')
    args = parser.parse_args()    
    if args.path:
        input_path = args.path
    else:
        print "You need to specify a path to your EML files."
        exit(0)

    if args.out:
        output_path = args.out
    else:
        print "You need to specify a path to write your attachments to."
        exit(0)
    
    for root, subdirs, files in os.walk(input_path):
        for file_names in files:
            eml_files = os.path.join(root, file_names)
            msg = email.message_from_file(open(eml_files))
            extractAttachment(msg, file_names, output_path)
                
if __name__ == "__main__":
    main()