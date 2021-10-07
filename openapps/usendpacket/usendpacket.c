#include "opendefs.h"
#include "usendpacket.h"
#include "openqueue.h"
#include "openserial.h"
#include "packetfunctions.h"
#include "scheduler.h"
#include "IEEE802154E.h"
#include "schedule.h"
#include "icmpv6rpl.h"
#include "idmanager.h"

//#define PACKET_TEST

//=========================== variables =======================================

usendpacket_vars_t usendpacket_vars;


static  uint8_t usendpacket_payload_True[]    = "0Omicke"; // O 버튼으로 인터럽트가 걸린 경우 payload 
static  uint8_t usendpacket_payload_False[]   = "0Xmicke"; // X 버튼으로 인터럽트가 걸린 경우 payload
// payload[0] = packetcount, payload[1] = answer, payload[2] = moteid 
static const uint8_t usendapcket_dst_addr[]   = {
   0xbb, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};
uint8_t packetCount=1; //PDR 측정을 위해 패킷 생성 시 증가하는 count 변수, Payload[0]에 담아서 보낸다.

//=========================== prototypes ======================================

void usendpacket_timer_cb(opentimers_id_t id);
void usendpacket_task_cb(bool answer);

//=========================== public ==========================================

void usendpacket_init(void) {

    // clear local variables
    memset(&usendpacket_vars,0,sizeof(usendpacket_vars_t));

    // register at UDP stack
    usendpacket_vars.desc.port              = WKP_UDP_INJECT;
    usendpacket_vars.desc.callbackReceive   = &usendpacket_receive;
    usendpacket_vars.desc.callbackSendDone  = &usendpacket_sendDone;
    openudp_register(&usendpacket_vars.desc);

    usendpacket_vars.period = USENDPACKET_PERIOD_MS; //(테스트용) 패킷 생성 주기 3초로 설정
    // start periodic timer
    usendpacket_vars.timerId = opentimers_create(TIMER_GENERAL_PURPOSE, TASKPRIO_UDP);

    usendpacket_payload_True[2] = idmanager_getMyID(ADDR_16B)->addr_16b[1]; // RPL protocol로 멀티 홉이 생기므로 어떤 기기에서 만든 패킷인지
                                                                            // 확인 할 필요가 있어 moteid를 payload[1]에 담는다. 
    usendpacket_payload_False[2] = idmanager_getMyID(ADDR_16B)->addr_16b[1]; 
    
#ifdef PACKET_TEST // opendefs.h에서 TEST 모드로 설정하면 타이머를 생성한다.
    packet_test = FALSE;
    opentimers_scheduleIn(
        usendpacket_vars.timerId,
        USENDPACKET_PERIOD_MS,
        TIME_MS,
        TIMER_PERIODIC,
        usendpacket_timer_cb
    );
#endif
}

void usendpacket_sendDone(OpenQueueEntry_t* msg, owerror_t error) {

    // free the packet buffer entry
    openqueue_freePacketBuffer(msg);

    // allow send next uinject packet
    usendpacket_vars.busySendingUsendpacket = FALSE;
}

void usendpacket_receive(OpenQueueEntry_t* pkt) {

    openqueue_freePacketBuffer(pkt);

    openserial_printError(
        COMPONENT_UINJECT,
        ERR_RCVD_ECHO_REPLY,
        (errorparameter_t)0,
        (errorparameter_t)0
    );
}

//=========================== private =========================================
#ifdef PACKET_TEST // TEST 용 타이머
void usendpacket_timer_cb(opentimers_id_t id){
    // calling the task directly as the timer_cb function is executed in
    // task mode by opentimer already
    usendpacket_task_cb(true);
}
#endif


void usendpacket_task_cb(bool answer) { // 패킷 생성 함수
    
#ifdef PACKET_TEST //TEST용 인 경우 한 기기가 패킷을 180개 까지 만들면 패킷생성 종료
 //   if (!packet_test) { return; }
    if (packetCount >= 181) {return;}

#endif
    
    OpenQueueEntry_t*    pkt;
    uint8_t              asnArray[5];
    open_addr_t          parentNeighbor;
    bool                 foundNeighbor;

    // don't run if not synch
    if (ieee154e_isSynch() == FALSE) {
        return;
    }

    // don't run on dagroot
    if (idmanager_getIsDAGroot()) {
        opentimers_destroy(usendpacket_vars.timerId);
        return;
    }

    foundNeighbor = icmpv6rpl_getPreferredParentEui64(&parentNeighbor);
    if (foundNeighbor==FALSE) {
        return;
    }

    if (schedule_hasManagedTxCellToNeighbor(&parentNeighbor) == FALSE) {
        return;
    }

    if (usendpacket_vars.busySendingUsendpacket==TRUE) {
        // don't continue if I'm still sending a previous uinject packet
        return;
    } 

    // if you get here, send a packet
    openserial_printInfo(COMPONENT_UINJECT, 255, 1, answer);
    
    // get a free packet buffer
    pkt = openqueue_getFreePacketBuffer(COMPONENT_UINJECT);
    if (pkt==NULL) {
        openserial_printError(
            COMPONENT_UINJECT,
            ERR_NO_FREE_PACKET_BUFFER,
            (errorparameter_t)0,
            (errorparameter_t)0
        );
        return;
    }

    pkt->owner                         = COMPONENT_UINJECT;
    pkt->creator                       = COMPONENT_UINJECT;
    pkt->l4_protocol                   = IANA_UDP;
    pkt->l4_destination_port           = WKP_UDP_INJECT;
    pkt->l4_sourcePortORicmpv6Type     = WKP_UDP_INJECT;
    pkt->l3_destinationAdd.type        = ADDR_128B;
    memcpy(&pkt->l3_destinationAdd.addr_128b[0],usendapcket_dst_addr,16);
    // add payload
    if (answer) { // O 버튼을 누른 경우나 Test용 인 경우 payload
        usendpacket_payload_True[0] = packetCount++; 
        packetfunctions_reserveHeaderSize(pkt,sizeof(usendpacket_payload_True)-1);
        memcpy(&pkt->payload[0],usendpacket_payload_True,sizeof(usendpacket_payload_True)-1);
    }
    else { // X 버튼을 누른 경우 payload
        usendpacket_payload_False[0] = packetCount++;
        packetfunctions_reserveHeaderSize(pkt,sizeof(usendpacket_payload_False)-1);
        memcpy(&pkt->payload[0],usendpacket_payload_False,sizeof(usendpacket_payload_False)-1);
    }
    packetfunctions_reserveHeaderSize(pkt,sizeof(uint16_t));
    pkt->payload[1] = (uint8_t)((usendpacket_vars.counter & 0xff00)>>8);
    pkt->payload[0] = (uint8_t)(usendpacket_vars.counter & 0x00ff);
    usendpacket_vars.counter++;

    packetfunctions_reserveHeaderSize(pkt,sizeof(asn_t));
    ieee154e_getAsn(asnArray);
    pkt->payload[0] = asnArray[0];
    pkt->payload[1] = asnArray[1];
    pkt->payload[2] = asnArray[2];
    pkt->payload[3] = asnArray[3];
    pkt->payload[4] = asnArray[4];

    if ((openudp_send(pkt))==E_FAIL) {
        openqueue_freePacketBuffer(pkt);
    } else {
        // set busySending to TRUE
        usendpacket_vars.busySendingUsendpacket = TRUE;
    }
}

