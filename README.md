Extachment
===========
Extract attachments from EML files.

You can read about it here: https://sysforensics.org/2015/04/extract-attachments-extachment.html

Help
=========

        python extachment.py -h
        usage: extachment.py [-h] [-p PATH] [-o OUT]
        
        Attempt to parse the attachment from EML messages.
        
        optional arguments:
        -h, --help show this help message and exit
        -p PATH, --path PATH Path to EML files.
        -o OUT, --out OUT Path to write attachments to.

Output
=======

        python extachment.py -p eml/ -o out/
        Could not process .DS_Store. Try manual extraction.
        Header of file: Bud1
        
        Email Name: 04c275b76dabf0cff85119942429e266e09394a1f4b2e47d0459544ae14cf904
        Magic: {\rt
        Saved File as: BL Draft.doc
        
        Email Name: 0beb40c866e815f000643064e8d3c2186dd1ca4ad60e3c4757795a56d39a85e5
        Magic: %PDF
        Saved File as: April invoice 963536.pdf
        
        Email Name: 1aa085f82eee9b74f4f88b5af03d46a428e15647b99e3a2b73768c1960de0177
        Magic: {\rt
        Saved File as: Order.doc
        
        Email Name: 21e6932ec611b3592811104f7e4165edc20ffb9d7c76a1060d597c3724e2c552
        Magic: {\rt
        Saved File as: bluegrill_bus_card.doc
        
        Email Name: 2cb553ffe1c898a1b6a586d4c232262d47ae1d390c66581cddf1387303e8ceed
        Magic: {\rt
        Saved File as: Airwaybill#-258-85695.doc
        
        Email Name: 423e753de0baad6fc755cb5a1118531ef21825883775c38b3ffdb76a7c360020
        Magic: {\rt
        Saved File as: PRODUCTION ORDER LIST.doc

Sample
=======

        xxd out/invoice7Q85M3KYN6YXOLRQOP.doc |head
        0000000: 7b5c 7274 6631 5c61 6e73 695c 616e 7369 {\rtf1\ansi\ansi
        0000010: 6370 6731 3235 315c 6465 6666 305c 6465 cpg1251\deff0\de
        0000020: 666c 616e 6731 3034 397b 5c66 6f6e 7474 flang1049{\fontt
        0000030: 626c 7b5c 6630 5c66 7377 6973 735c 6663 bl{\f0\fswiss\fc
        0000040: 6861 7273 6574 3020 4172 6961 6c3b 7d7b harset0 Arial;}{
        0000050: 5c66 315c 6673 7769 7373 5c66 6368 6172 \f1\fswiss\fchar
        0000060: 7365 7432 3034 7b5c 2a5c 666e 616d 6520 set204{\*\fname
        0000070: 4172 6961 6c3b 7d41 7269 616c 2043 5952 Arial;}Arial CYR
        0000080: 3b7d 7d0d 0a7b 5c2a 5c67 656e 6572 6174 ;}}..{\*\generat
        0000090: 6f72 204d 7366 7465 6469 7420 352e 3431 or Msftedit 5.41
