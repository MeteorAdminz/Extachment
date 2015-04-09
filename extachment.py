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
Version 0.3

Reference: http://www.decalage.info/python/oletools
Reference: https://github.com/mattgwwalker/msg-extractor
'''
import os, re
import email
import argparse
import olefile
import csv
import stat                               #Python Standard Library - constants and functions for interpreting os results
import time
import hashlib


# check command line directory entries to validate the directories exist
def ValidateDirectory(theDir):

    # Validate the path is a directory
    if not os.path.isdir(theDir):
        raise argparse.ArgumentTypeError('Directory does not exist')

    # Validate the path is readable
    if os.access(theDir, os.R_OK):
        return theDir
    else:
        raise argparse.ArgumentTypeError('Directory is not readable')

def extractAttachment(msg, eml_files, output_path, CSVWriter):
    if len(msg.get_payload()) > 2:
        if isinstance(msg.get_payload(), str):
            try:
                extractOLEFormat(eml_files, output_path, CSVWriter)
            except IOError:
                #print 'Could not process %s. Try manual extraction.' % (eml_files)
                #print '\tHeader of file: %s\n' % (msg.get_payload()[:8])
                pass

        elif isinstance(msg.get_payload(), list):
            count = 0
            while count < len(msg.get_payload()):
                payload = msg.get_payload()[count]
                filename = payload.get_filename()
                if filename is not None:
                    try:
                        magic = payload.get_payload(decode=True)[:4]
                    except TypeError:
                        magic = "None"                    
                    # Print the magic deader and the filename for reference.
                    printIT(eml_files, magic, filename)
                    # Write the payload out.
                    writeFile(filename, payload, output_path)
                    HashFile(os.path.join(output_path, filename), filename, CSVWriter)
                count += 1

    elif len(msg.get_payload()) == 2:
        payload = msg.get_payload()[1]
        filename = payload.get_filename()
        try:
            magic = payload.get_payload(decode=True)[:4]
        except TypeError:
            magic = "None"
        # Print the magic deader and the filename for reference.
        printIT(eml_files, magic, filename)
        # Write the payload out.
        writeFile(filename, payload, output_path)      
        HashFile(os.path.join(output_path, filename), filename, CSVWriter)

    elif len(msg.get_payload()) == 1:
        attachment = msg.get_payload()[0]
        payload = attachment.get_payload()[1]
        filename = attachment.get_payload()[1].get_filename()
        try:
            magic = payload.get_payload(decode=True)[:4]
        except TypeError:
            magic = "None"        
        # Print the magic deader and the filename for reference.
        printIT(eml_files, magic, filename)
        # Write the payload out.
        writeFile(filename, payload, output_path)
        HashFile(os.path.join(output_path, filename), filename, CSVWriter)
    #else:
    #    print 'Could not process %s\t%s' % (eml_files, len(msg.get_payload()))

def extractOLEFormat(eml_files, output_path, CSVWriter):
    data = '__substg1.0_37010102'
    filename = olefile.OleFileIO(eml_files)
    msg = olefile.OleFileIO(eml_files)
    attachmentDirs = []
    for directories in msg.listdir():
        if directories[0].startswith('__attach') and directories[0] not in attachmentDirs:
            attachmentDirs.append(directories[0])

    for dir in attachmentDirs:
        filename = [dir, data]
        if isinstance(filename, list):
            filenames = "/".join(filename)
            filename = msg.openstream(dir + '/' + '__substg1.0_3707001F').read().replace('\000', '')
            payload = msg.openstream(filenames).read()
            magic = payload[:4]
            # Print the magic deader and the filename for reference.
            printIT(eml_files, magic, filename)
            # Write the payload out.
            writeFile(filename, payload, output_path)
            HashFile(os.path.join(output_path, filename), filename, CSVWriter)
            
def printIT(eml_files, magic, filename):
    print 'Email Name: %s\n\tMagic: %s\n\tSaved File as: %s\n' % (eml_files, magic, filename)

def writeFile(filename, payload, output_path):
    try:
        #build path was missing \\ before file name
        fp = os.path.join(output_path, filename)
        #open file        
        d = open(fp, 'wb')
        #        
        d.write(payload)
        d.close()
        return fp
    except:
        print "couldn't open file to write " 
        

def writeOLE(filename, payload, output_path):
    open(os.path.join(output_path + filename), 'wb')

#hash file and output file stats to csv report
def HashFile(theFile, simpleName, o_result):

    # Verify that the path is valid
    if os.path.exists(theFile):

        #Verify that the path is not a symbolic link
        if not os.path.islink(theFile):

            #Verify that the file is real
            if os.path.isfile(theFile):

                try:
                    #Attempt to open the file
                    f = open(theFile, 'rb')
                except IOError:
                    #if open fails report the error
                    print 'Open Failed: ' + theFile
                    return
                else:
                    try:
                        # Attempt to read the file
                        rd = f.read()
                    except IOError:
                        # if read fails, then close the file and report error
                        f.close()
                        print 'Read Failed: ' + theFile
                        return
                    else:
                        #success the file is open and we can read from it
                        #lets query the file stats

                        theFileStats =  os.stat(theFile)
                        (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(theFile)

                        #Print the simple file name
                        print "Processing File: " + theFile

                        # print the size of the file in Bytes
                        fileSize = str(size)

                        #print MAC Times
                        modifiedTime = time.ctime(mtime)
                        accessTime = time.ctime(atime)
                        createdTime = time.ctime(ctime)
                        
                        ownerID = str(uid)
                        groupID = str(gid)
                        fileMode = bin(mode)

                        #process the file hashes

                        if args.md5:
                            #Calcuation and Print the MD5
                            hash = hashlib.md5()
                            hash.update(rd)
                            hexMD5 = hash.hexdigest()
                            hashValue = hexMD5.upper()
                        elif args.sha256:
                            hash=hashlib.sha256()
                            hash.update(rd)
                            hexSHA256 = hash.hexdigest()
                            hashValue = hexSHA256.upper()
                        elif args.sha512:
                            #Calculate and Print the SHA512
                            hash=hashlib.sha512()
                            hash.update(rd)
                            hexSHA512 = hash.hexdigest()
                            hashValue = hexSHA512.upper()
                        else:
                            print 'Hash not Selected'
                        #File processing completed
                        #Close the Active File
                        print "================================"
                        f.close()
                        
                        # write one row to the output file
                                                
                        o_result.writeCSVRow(simpleName, theFile, fileSize, modifiedTime, accessTime, createdTime, hashValue, ownerID, groupID, mode)
                        
                        return True
            else:
                print "[" + repr(simpleName) + ", Skipped NOT a File]"
                return False
        else:
            print "[" + repr(simpleName) + ", Skipped Link NOT a File ]"
            return False
    else:
            print "[" + repr(simpleName) + ", Path does NOT exist]"        
    return False

# End HashFile Function ===================================

#define class for writing csv report file
class _CSVWriter:

    def __init__(self, fileName, hashType):
        try:
            # create a writer object and then write the header row
            self.csvFile = open(fileName, 'wb')
            self.writer = csv.writer(self.csvFile, delimiter=',', quoting=csv.QUOTE_ALL)
            self.writer.writerow( ('File', 'Path', 'Size', 'Modified Time', 'Access Time', 'Created Time', hashType, 'Owner', 'Group', 'Mode') )
        except:
            print 'CSV File Failure'

    def writeCSVRow(self, fileName, filePath, fileSize, mTime, aTime, cTime, hashVal, own, grp, mod):
        self.writer.writerow( (fileName, filePath, fileSize, mTime, aTime, cTime, hashVal, own, grp, mod))

    def writerClose(self):
        self.csvFile.close()



def main():
    parser = argparse.ArgumentParser(description='Attempt to parse the attachment from EML messages.')
    parser.add_argument('-p', '--path', type= ValidateDirectory, required=True, help='Path to EML files.')
    parser.add_argument('-o', '--out', type= ValidateDirectory, required=True, help='Path to write attachments to.')
    
    #add options for hashing the attachments
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--md5',       help = 'specifies MD5 algorithm',       action='store_true')
    group.add_argument('--sha256',   help = 'specifies SHA256 algorithm',   action='store_true')   
    group.add_argument('--sha512',   help = 'specifies SHA512 algorithm',   action='store_true')          
    
    
    global args
    # parse hash option
    args = parser.parse_args()    
    if args.md5:
        gl_hashType = 'MD5'
    elif args.sha256:
        gl_hashType = 'SHA256'
    elif args.sha512:
        gl_hashType = 'SHA512'
    else:
        gl_hashType = "Unknown"
        
    # removed error checking here and including a function    type = ValidateDirectory 
    if args.path:
        input_path = args.path
    
    if args.out:
        output_path = args.out
        
        
   # create cvs instance
    oCVS = _CSVWriter(output_path +'AttachmentReport.csv', gl_hashType)
    
    for root, subdirs, files in os.walk(input_path):
        for file_names in files:
            eml_files = os.path.join(root, file_names)
            msg = email.message_from_file(open(eml_files))
            extractAttachment(msg, eml_files, output_path, oCVS)



if __name__ == "__main__":
    main()
