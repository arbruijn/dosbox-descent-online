/*
 *  Copyright (C) 2002-2021  The DOSBox Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */


#include <string.h>
#include <ctype.h>
#include "regs.h"
#include "callback.h"
#include "dos_system.h"
#include "dos_inc.h"
#include "setup.h"
#include "support.h"
#include "bios_disk.h"
#include "cpu.h"
#include "paging.h"

#define EGOVXD_LOG LOG(LOG_MISC,LOG_ERROR)

static int call_ego;
extern Bit32u ego_hack;

static bool EGOVXD_Handler(void) {
	if (reg_ah!=0x16) return false;		// not handled here, continue chain

	//PhysPt data = PhysMake(SegValue(es),reg_bx);
	EGOVXD_LOG("VXD: INT 2F %04X BX= %04X CX=%04X",reg_ax,reg_bx,reg_cx);
	//CALLBACK_SCF(false); // carry flag cleared for all functions (undocumented); only set on error
	switch (reg_ax) {
		case 0x1600:	/* Install check */
						reg_al = 0x01;
						break;
		case 0x1684:
			if (reg_bx == 0x3887) {
				RealPt cbptr=CALLBACK_RealPointer(call_ego);
				SegSet16(es, RealSeg(cbptr));
				reg_edi = RealOff(cbptr);
				break;
			}
		default:		LOG(LOG_MISC,LOG_ERROR)("VXD: Unknown call : %04X",reg_ax);
						//reg_ax = VXD_ERROR_INVALID_FUNCTION;
						//CALLBACK_SCF(true);
						break;
	}
	return true;
}

// flags, ?, cmd, len, ?
static unsigned char pkt_connected[] = { 0,0, 0,1, 0,0x79, 0,0, 0,0 };
static unsigned char pkt_creategame[] = {
	0,0, 0,0, 0,0xd0, 0,199, 0,0,
	22,
'B','A','B','Y','B','E','A','R',0,
'B','A','Y','3','2','Z',0,0,0,
'B','E','A','R','C','L','A','W',0,
'B','U','B','A','M','I','N','E',0,
'F','L','A','G','C','A','P',0,0,
'G','O','A','L','P','O','S','T',0,
'G','O','T','C','H','A',0,0,0,
'H','A','L','L','S','1','0','Z',0,
'J','O','N','N','Y',0,0,0,0,
'M','E','G','A','D','E','T','H',0,
'O','G','R','E',0,0,0,0,0,
'O','N','L','I','N','E',0,0,0,
'P','A','N','C','A','K','E',0,0,
'Q','U','I','C','K','Y',0,0,0,
'R','O','N','D','W','E','G','O',0,
'S','P','I','D','E','R',0,0,0,
'S','T','O','N','E','R',0,0,0,
'T','E','M','P','L','E',0,0,0,
'T','O','U','R','N','E','Y',0,0,
'U','L','T','I','M','A','T','E',0,
'V','2',0,0,0,0,0,0,0,
'Y','I','K','E','S',0,0,0,0};

//static unsigned char pkt_creategame[] = {
//	0,0, 0,0, 0,0xd0, 0,10, 0,0,
//	1, 'B', 'U', 'B', 'A', 'M', 'I', 'N', 'E', 0 };
static unsigned char pkt_hello[] = {
	1,2, 0,0, 0,0xd1, 0,28, 0,0,
	'W', 'e', 'l', 'c', 'o', 'm', 'e', '.', ' ',
	'P', 'r', 'e', 's', 's', ' ', 'F', '1', '0', ' ', 't', 'o', ' ',
	'p', 'l', 'a', 'y', '.', 0 };
static int hasinit = 0;
static int hassend = 0;
static int lastcmd = 0;

static unsigned char netgame[0x17c + 10];
static int hasnet = 0;

static Bit32u PhysMakeProt(Bit16u selector, Bit32u offset)
{
	Descriptor desc;
	if (cpu.gdt.GetDescriptor(selector,desc)) return desc.GetBase()+offset;
	return 0;
};

static Bitu EGOVXD_EGO_Handler(void) {
	PhysPt buf;
	unsigned short hdr[5];
	unsigned char data[16];
	if (reg_eax != 1 && reg_eax != 2)
		LOG(LOG_MISC,LOG_ERROR)("EGO:  Call : %04X ebx %x",reg_ax,reg_ebx);
	switch (reg_eax) {
		case 0: // Get version
			reg_eax = 0x400;
			//ego_hack = 0x1024a930;
			break;
		case 1: // Send data
			//buf = SegPhys(es) + reg_ebx;
			buf = reg_ebx;
			CPU_SET_CRX(0, CPU_GET_CRX(0)|0x80000001);
			//PAGING_ClearTLB();
			MEM_BlockRead(buf, hdr, sizeof(hdr));
			MEM_BlockRead(buf + 10, data, sizeof(data));
			lastcmd = (hdr[2] >> 8) | ((hdr[2] & 0xff) << 8);
			if (hdr[2] == 0xce00) {
				MEM_BlockRead(buf, netgame, sizeof(netgame));
				hasnet = 1;
			}
			CPU_SET_CRX(0, CPU_GET_CRX(0)&~0x80000001);
			char logbuf[80];
			snprintf(logbuf, sizeof(logbuf), "EGO:  Send %d addr %x: %04x %04x %04x %04x %04x",
				reg_ecx, (Bit32u)buf, hdr[0], hdr[1], hdr[2], hdr[3], hdr[4]);
			LOG(LOG_MISC,LOG_ERROR)("%s", logbuf);
			snprintf(logbuf, sizeof(logbuf), "EGO:  %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
				data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
				data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);
			LOG(LOG_MISC,LOG_ERROR)("%s", logbuf);
			hassend = 1;
			break;
		case 2: // Get data
			buf = reg_ebx;
			unsigned char *outdata = NULL;
			int outsize = 0;
			if (hassend && !hasinit) {
				hasinit = 1;
				outdata = pkt_connected; outsize = sizeof(pkt_connected);
			}
			if (lastcmd == 0xd0) {
				outdata = pkt_creategame; outsize = sizeof(pkt_creategame);
			}
			if (lastcmd == 0xcf) { //hasnet) {
				hasnet = 0;
				netgame[0] = netgame[1] = 0;
				netgame[5] = 0xcf;
				netgame[10] = '!'; // pkt type
				netgame[12] = 2; // num players
				outdata = netgame; outsize = sizeof(netgame);
			}
			if (lastcmd == 0xc8) {
				outdata = pkt_hello; outsize = sizeof(pkt_hello);
			}
			lastcmd = 0;
			if (outdata) {
				CPU_SET_CRX(0, CPU_GET_CRX(0)|0x80000001);
				//PAGING_ClearTLB();

				MEM_BlockWrite(buf, outdata, outsize);
				reg_eax = outsize;

				MEM_BlockRead(buf, hdr, sizeof(hdr));
				MEM_BlockRead(buf + 10, data, sizeof(data));
				CPU_SET_CRX(0, CPU_GET_CRX(0)&~0x80000001);
				char logbuf[80];
				snprintf(logbuf, sizeof(logbuf), "EGO:  Recv %d: %04x %04x %04x %04x %04x",
					reg_eax, hdr[0], hdr[1], hdr[2], hdr[3], hdr[4]);
				LOG(LOG_MISC,LOG_ERROR)("%s", logbuf);
				break;

			}
			//buf[1] = cmd;
			//*(short *)(buf + 6) = 
			reg_eax = 0;
			break;
	}
	return CBRET_NONE;
}

void EGOVXD_ShutDown(Section* /*sec*/) {
	//delete mscdex;
	//mscdex = 0;
	//curReqheaderPtr = 0;
}

void EGOVXD_Init(Section* sec) {
	// AddDestroy func
	sec->AddDestroyFunction(&EGOVXD_ShutDown);
	/* Register the mscdex device */
	//DOS_Device * newdev = new device_VXD();
	//DOS_AddDevice(newdev);
	//curReqheaderPtr = 0;
	/* Add Multiplexer */
	DOS_AddMultiplexHandler(EGOVXD_Handler);
	/* Create VXD */
	//mscdex = new CMscdex;
        call_ego=CALLBACK_Allocate();
        CALLBACK_Setup(call_ego,&EGOVXD_EGO_Handler,CB_RETF,"vxd ego");
}
