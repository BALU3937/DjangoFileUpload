from django.shortcuts import render
from django.core.files.storage import FileSystemStorage

from . models import File
import os, datetime
import pefile
import struct
import io
import requests
import os.path,time

from . import trail


IMAGE_FILE_MACHINE_I386=332
IMAGE_FILE_MACHINE_IA64=512
IMAGE_FILE_MACHINE_AMD64=34404

# Create your views here.

def index(request):
    if request.method == 'POST' and request.FILES['file']:
        upload_file = request.FILES['file']
        extension = os.path.splitext(upload_file.name)[1]
        rename = datetime.datetime.now().strftime("%Y_%m_%d %H_%M_%S") + extension
        fss = FileSystemStorage()

        filename = fss.save(rename, upload_file)

        file = File(file=rename)

        file.save()

        upload_file_path = fss.path(filename)

        md5=trail.hash_value(upload_file_path)
        f = upload_file_path
        fl = open(f, "rb")
        s = fl.read(5)
        byte_range = bytearray(s)
        date_header, timestamp = struct.unpack('>BL', byte_range)
        print(date_header)
        if ( date_header!=77):
            print(" Not an EXE file")
        else:
            fl.seek(60)
            s = fl.read(4)
            header_offset = struct.unpack("<L", s)[0]
            fl.seek(header_offset + 4)
            s = fl.read(2)
            machine = struct.unpack("<H", s)[0]

            if machine == IMAGE_FILE_MACHINE_I386:
                print(" Image Type = IA-32 (32-bit x86)")
                fp = open('PE Analysis.txt', 'a')
                fp.write("Image Type = IA-32 (32-bit x86)")
                fp.write('\n\n')
                fp.close()
            elif machine == IMAGE_FILE_MACHINE_IA64:
                print(" Image Type = IA-64 (Itanium)")
                fp = open('PE Analysis.txt', 'a')
                fp.write("Image Type = IA-64 (Itanium)")
                fp.write('\n\n')
                fp.close()
            elif machine == IMAGE_FILE_MACHINE_AMD64:
                print(" Image Type = AMD64 (64-bit x86)")
                fp = open('PE Analysis.txt', 'a')
                fp.write("Image Type = AMD64 (64-bit x86)")
                fp.write('\n\n')
                fp.close()
            else:
                print(" Unknown architecture")

            print('\n File Size = ' + trail.file_size(f))
            print('\n Last Modified Date = %s' % time.ctime(os.path.getmtime(f)))
            print('\n Created Date = %s' % time.ctime(os.path.getctime(f)))

            fp = open('PE Analysis.txt', 'a')
            fp.write('File Size = ' + trail.file_size(f))
            fp.write('\n\nLast Modified Date: %s' % time.ctime(os.path.getmtime(f)))
            fp.write('\n\nCreated Date: %s' % time.ctime(os.path.getctime(f)))
            fp.write('\n')
            fp.write('\n')
            fp.close()
        fl.close()
        virustotal=trail.VT_Request('eca6223108ae025265a09a1723ddc2d7396c31ab41f720428f9a9fc7bd4cb95e',md5,upload_file_path)
        if(isinstance(virustotal,str)):
            output=virustotal
        else:
             md=virustotal[0]
             sha1=virustotal[1]
             sha256=virustotal[2]
             positives=virustotal[3]
             total=virustotal[4]


        return render(request, 'file/hello.html', {'upload_file_path': upload_file_path,'md5':virustotal[0],'sha1':virustotal[1],'sha256':virustotal[2],'positives':virustotal[3],'total':virustotal[4]})

    else:
        return render(request, 'file/index.html')



