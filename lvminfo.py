#!/usr/bin/python

'''
 Copyright (c) 2013, Jeffrey Dileo
 All rights reserved.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
 
 1. Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

'''


import os
import re
import sys
import struct
import magic

def getRow(buf):
	for i in xrange(0, len(buf), 16):
		yield buf[i:i+16]

def hexdump(bytes):
	g = getRow(bytes)
	outstr = ""
	try:
		while(True):
			line = next(g); ll = len(line)
			out1 = ""; out2 = ""
			for i in range(16):
				if(i == 8):
					out1 += " "
					out2 += " "
				if(i < ll):
					out1 += '%02X' % ord(line[i])
					if(0x20 <= ord(line[i]) <= 0x7e):
						out2 += line[i]
					else:
						out2 += "."
				else:
					out1 += "  "
				out1 += " "
			outstr += out1 + "  :  " + out2 + "\n"
	except StopIteration: outstr = outstr[:-1]
	return outstr

"""
/* from NetBSD's src/sys/net/if_ethersubr.c */
uint32_t
crc32_le(uint32_t crc, const uint8_t *buf, size_t len)
{
        static const uint32_t crctab[] = {
                0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
                0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
                0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
                0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
        };
        size_t i;

        for (i = 0; i < len; i++) {
                crc ^= buf[i];
                crc = (crc >> 4) ^ crctab[crc & 0xf];
                crc = (crc >> 4) ^ crctab[crc & 0xf];
        }

        return (crc);
}
"""

def crc32_le(buf):
	crc = 0xf597a6cf

	crctab = [ 0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
		0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
		0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
		0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c ]
        
	for i in range(len(buf)):
		crc ^= ord(buf[i])
		crc = (crc >> 4) ^ crctab[crc & 0xf]
		crc = (crc >> 4) ^ crctab[crc & 0xf]
	
	return crc

def main():
	if (len(sys.argv) < 2):
		print "usage: %s <filename> [offset]" % sys.argv[0]
		sys.exit(2)
	
	try:
		fd = open(sys.argv[1],'r')
	
	except:
	    print "invalid filename"
	    sys.exit(2)

	filesize = os.path.getsize(sys.argv[1])
	print "Size of %s: %dB" % (sys.argv[1], filesize) 	

	offset = 0
	if(len(sys.argv) == 3):
		offset = int(sys.argv[2])
		fd.seek(offset)
	
	pvlabelsector = 1 # default

	sector0 = fd.read(512)
	sector1 = fd.read(512)
	sector2 = fd.read(512)
	sector3 = fd.read(512)
	pvlabel = ""
	if len(sector0) != 512:
		print "\x1b[31;1m[Error]\x1b[0m Image too small."
		sys.exit(2)

	if sector0.find("LABELONE") == 0:
		pvlabelsector = 0
	
	if(pvlabelsector == 1):
		if len(sector1) != 512:
			print "\x1b[31;1m[Error]\x1b[0m Image too small."
			sys.exit(2)

		if sector1.find("LABELONE") == 0:
			pvlabelsector = 1
		else:
			if len(sector2) != 512:
				print "\x1b[31;1m[Error]\x1b[0m Image too small."
				sys.exit(2)
			if sector2.find("LABELONE") == 0:
				pvlabelsector = 2
			else:
				if len(sector3) != 512:
					print "\x1b[31;1m[Error]\x1b[0m Image too small."
					sys.exit(2)
				if sector3.find("LABELONE") == 0:
					pvlabelsector = 3
				else:
					print "\x1b[31;1m[Error]\x1b[0m %s does not contain LVM PV label. Found:" % sys.argv[1]
					print hexdump(sector0)
					print hexdump(sector1)
					print hexdump(sector2)
					print hexdump(sector3)
					sys.exit(3)

	print "\x1b[34m[Info]\x1b[0m LVM PV label found."
	sectors = [sector0, sector1, sector2, sector3]
	pvlabel = sectors[pvlabelsector]
	if pvlabelsector != 1:
		print "\x1b[31m[Alert]\x1b[0m LVM PV label is being stored in sector %d" %pvlabelsector

	for i in range(4):
		if(i != pvlabelsector):
			if not re.match('^[\\x00]{512}$', sectors[i] ):
				print "\x1b[31m[Alert]\x1b[0m Sector %d is not empty:" %pvlabelsector
				print hexdump(sectors[i])

	supplied_pv_crc = struct.unpack("@I", pvlabel[16:20])[0]
	print "PV Label FastCRC32: " + hex(supplied_pv_crc)
	calculated_pv_crc = crc32_le(pvlabel[20:])
	if supplied_pv_crc != calculated_pv_crc:
		print "\x1b[31m[Alert]\x1b[0m FastCRC32 on image does not match calculated FastCRC32."
		print "Calculated PV Label FastCRC32 = \x1b[31m0x%08x\x1b[0m" % calculated_pv_crc

	pv_meta_offset = struct.unpack("@I", pvlabel[20:24])[0]
	pv_type = pvlabel[24:32]

	print "PV Type: \"%s\"" %  pv_type

	unformatted_pv_id = pvlabel[pv_meta_offset:pv_meta_offset+32]
	print "PV UUID: " + '-'.join([unformatted_pv_id[i:i+4] for i in range(0, len(unformatted_pv_id), 4)])

	pv_size = struct.unpack("@L", pvlabel[pv_meta_offset+32:pv_meta_offset+40])[0]	

	print "PV Size: %dB" % pv_size
	if( pv_size != filesize ):
		print "\x1b[31m[Alert]\x1b[0m PV size does not match image size."
		if pv_size < filesize:
			print "===> PV size is smaller than image size. Will search for data after end of PV."
		else:
			print "===> Image size is smaller than PV size. The image file being used is either incomplete or truncated."

	data_offset = struct.unpack("@L", pvlabel[pv_meta_offset+40:pv_meta_offset+48])[0]

	print "Data Offset (data in logical volume): 0x%08x [%d]" % (data_offset,data_offset)

	data_size_idk = struct.unpack("@L", pvlabel[pv_meta_offset+48:pv_meta_offset+56])[0]
	
	pv_meta_data_header_offset = struct.unpack("@L", pvlabel[pv_meta_offset+72:pv_meta_offset+80])[0]

	print "PV Meta Data Header Offset: 0x%08x [%d]" % (pv_meta_data_header_offset,pv_meta_data_header_offset)

	pv_meta_data_header_size = struct.unpack("@L", pvlabel[pv_meta_offset+80:pv_meta_offset+88])[0]

	print "PV Meta Data Header Size: %dB" % pv_meta_data_header_size

	fd.seek(offset + pv_meta_data_header_offset, 0)
	pv_meta_data_header = fd.read(512)

	if len(pv_meta_data_header) < 512:
		print "\x1b[31;1m[Error]\x1b[0m Image too small. %s does not contain entire PV meta data area." % sys.argv[1]
		sys.exit(4)

	print "\x1b[34m[Info]\x1b[0m LVM PV Metadata Header found."

	supplied_pv_meta_data_header_crc = struct.unpack("@I", pv_meta_data_header[:4])[0]

	print "PV Metadata Header FastCRC32: " + hex(supplied_pv_meta_data_header_crc)

	
	calculated_pv_meta_data_header_crc = crc32_le(pv_meta_data_header[4:])

	if supplied_pv_meta_data_header_crc != calculated_pv_meta_data_header_crc:
		print "\x1b[31m[Alert]\x1b[0m FastCRC32 on image does not match calculated FastCRC32."
		print "Calculated PV Metadata Header FastCRC32 = \x1b[31m0x%08x\x1b[0m" % calculated_pv_meta_data_header_crc

	pv_meta_data_header_magic_string = " LVM2 x[5A%r0N*>"
	supplied_magic_string = pv_meta_data_header[4:20]

	if(pv_meta_data_header_magic_string != supplied_magic_string):
		print "\x1b[31m[Alert]\x1b[0m Magic string \"%s\" is not in the PV Metadata Header." % pv_meta_data_header_magic_string

	pv_meta_data_header_version = struct.unpack("@I", pv_meta_data_header[20:24])[0]

	print "PV Metadata Header Version: %d" % pv_meta_data_header_version

	pv_meta_data_header_absolute_start = struct.unpack("@L", pv_meta_data_header[24:32])[0]
	
	if (pv_meta_data_header_absolute_start != pv_meta_data_header_offset):
		print ("\x1b[31m[Alert]\x1b[0m PV Label value for Metadata Header Offset" +
			"!= PV Metadata value for Metadata Header Offset [\x1b[31m%s\x1b[0m]" % hex(pv_meta_data_header_absolute_start) )

	pv_meta_data_header_absolute_size = struct.unpack("@L", pv_meta_data_header[32:40])[0]

	if (pv_meta_data_header_absolute_size != pv_meta_data_header_size):
		print ("\x1b[31m[Alert]\x1b[0m PV Label value for Metadata Header Size" +
			"!= PV Metadata value for Metadata Header Size [\x1b[31m%s\x1b[0m]" % hex(pv_meta_data_header_absolute_size) )

	vg_meta_offset = struct.unpack("@L", pv_meta_data_header[40:48])[0]
	
	print "VG Offset (from PV Metadata Header Start): 0x%08x [%d]" % (vg_meta_offset, vg_meta_offset)

	vg_meta_size = struct.unpack("@L", pv_meta_data_header[48:56])[0]

	print "VG Metadata Size: %dB" % vg_meta_size

	if(vg_meta_size == 0):
		print "\x1b[31;1m[Error]\x1b[0m %s does not contain a volume group." % sys.argv[1]
		sys.exit(1)

	vg_supplied_crc = struct.unpack("@L", pv_meta_data_header[56:64])[0]

	print "VG FastCRC32: " + hex(vg_supplied_crc)

	fd.seek(offset + pv_meta_data_header_offset + vg_meta_offset, 0)
	vg_meta_data = fd.read(vg_meta_size)
	if len(vg_meta_data) < vg_meta_size:
		print "\x1b[31;1m[Error]\x1b[0m Image too small. %s does not contain entire VG metadata block." % sys.argv[1]
		sys.exit(5)

	print "\x1b[34m[Info]\x1b[0m LVM Volume Group Metadata found."

	#print "Volume Group:"
	#print "="*80
	#print vg_meta_data
	#print "="*80

	vg_meta_lines = vg_meta_data.split("\n")
	extent_size = 0
	pv_start = 0
	lv_start = 0
	logical_volumes = []
	pv = {}
	vg_name = vg_meta_lines[0][:-2]


	for i in range(len(vg_meta_lines)):
		if vg_meta_lines[i].startswith("extent_size"):
			extent_size = int(vg_meta_lines[i].split(" = ")[-1], 10)
		if vg_meta_lines[i] == "physical_volumes {":
			pv_start = i
			continue
		if vg_meta_lines[i] == "logical_volumes {":
			lv_start = i
			break


	for i in range(pv_start, len(vg_meta_lines)):
		if vg_meta_lines[i].endswith(" {") and vg_meta_lines[i+1].startswith("id = "):
			pv['name'] = vg_meta_lines[i][:-2]
			pv['id'] = vg_meta_lines[i+1].split(" = ")[-1].strip("\"")
		if vg_meta_lines[i].startswith("dev_size = "):
			pv['dev_size'] = int(vg_meta_lines[i].split(" = ")[-1], 10)
		if vg_meta_lines[i].startswith("pe_count = "):
			pv['pe_count'] = int(vg_meta_lines[i].split(" = ")[-1], 10)
		if vg_meta_lines[i].endswith("}") and vg_meta_lines[i+1].endswith("}"):
			break

	#print pv	
	if(lv_start != 0):
		for i in range(lv_start, len(vg_meta_lines)):
			if vg_meta_lines[i].endswith(" {") and vg_meta_lines[i+1].startswith("id = "):
				logical_volumes.append((vg_meta_lines[i][:-2],i,{"id": vg_meta_lines[i+1].split(" = ")[-1].strip("\"") }))

	
	#print logical_volumes
	
	for l in range(len(logical_volumes)):
		logical_volumes[l][2]["start_extent"] = 0
		logical_volumes[l][2]["extent_count"] = 0
		for i in range(logical_volumes[l][1], len(vg_meta_lines)):
			if vg_meta_lines[i].startswith("start_extent = "):
				logical_volumes[l][2]["start_extent"] = int( vg_meta_lines[i].split(" = ")[-1] ,10)
				continue
			if vg_meta_lines[i].startswith("extent_count = "):
				logical_volumes[l][2]["extent_count"] = int( vg_meta_lines[i].split(" = ")[-1] ,10)
				break

	#print logical_volumes

	#if( vg_size != pv_size ):
	#	print "\x1b[31m[Alert]\x1b[0m VG size does not match PV size."
	#	if vg_size < pv_size:
	#		print "===> \x1b[34m[Info]\x1b[0m VG size is smaller than PV size. There may be more data after the end of the VG."
	#	else:
	#		print "===> \x1b[31;1m[Error]\x1b[0m PV size is smaller than VG size. This image file is corrupted."

	mage = magic.open(0)
	mage.load()

	#print logical_volumes
	prev_extents = 0

	print "Volume Group: %s" % vg_name
	print "\tLogical Volumes:"
	if(len(logical_volumes)==0):
		print "\tNo logical volumes found."
	for l in range(len(logical_volumes)):
		print "\t+ " + logical_volumes[l][0]
		print "\t\tID: " + logical_volumes[l][2]['id']
		lv_size = logical_volumes[l][2]['extent_count']*extent_size*512
		print "\t\tSize: %dB" % lv_size
		lv_offset = data_offset + prev_extents*extent_size*512
		print "\t\tOffset: 0x%08x [%dB]" % (lv_offset,lv_offset)
		fd.seek(offset + lv_offset)
		beginning = fd.read(2048)
		print "\t\tType: %s" % mage.buffer(beginning)
		prev_extents += logical_volumes[l][2]['extent_count']

	print ""

	free_space = ((pv['pe_count'] - prev_extents)*extent_size*512)

	print "Physical Group: %s" % pv['name']
	print "\t " + "ID: " + pv['id']
	print "\t " + "Size: %dB" % (pv['dev_size']*512)
	print "\t " + "Available Space: %dB" % free_space

	if pv['dev_size']*512 != pv_size:
		print "\x1b[31,1m[Error]\x1b[0m PV size in PV Label != PV size in VG Metadata."
		sys.exit(7)

	if( free_space > 0 ):
		print "\x1b[34m[Info]\x1b[0m Searching for magic values in free space."

		search_size = 8192
		fd.seek(offset + pv_size - free_space,0)
		found_count = 0
		for i in range((free_space / search_size) + 1):
			if i%1024 == 0:
				sys.stdout.write(".")
				sys.stdout.flush()
			fd.seek(offset + (pv_size - free_space) + i*search_size ,0)
			unknown = fd.read(search_size*2)
			ulo = unknown.find("LABELONE")
			ulvm = unknown.find("LVM2 x[5A%r0N*>")
			if(ulo != -1):
				found_count += 1
				print "\n\x1b[34m[Info]\x1b[0m Found \"LABELONE\" at %dB." % ( (pv_size - free_space) + i*search_size + ulo )
			if(ulvm != -1):
				found_count += 1
				print "\n\x1b[34m[Info]\x1b[0m Found \"LVM2 x[5A%%r0N*>\" at %dB." % ( (pv_size - free_space) + i*search_size + ulvm )
			

		if(found_count == 0):
			print "No magic values found."	
	

if __name__ == "__main__":
	main()
