#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
using namespace std;
typedef struct
{
  uint32_t addr;
  uint32_t len;
  uint32_t if_index;
  uint32_t nexthop;
  uint32_t metric;
} RoutingTableEntry;
#define RIP_MAX_ENTRY 25
typedef uint32_t in_addr_t;
typedef struct
{
  // all fields are big endian
  // we don't store 'family', as it is always 2(response) and 0(request)
  // we don't store 'tag', as it is always 0
  uint32_t addr;
  uint32_t mask;
  uint32_t nexthop;
  uint32_t metric;
} RipEntry;

typedef struct
{
  uint32_t numEntries;
  // all fields below are big endian
  uint8_t command;
  // we don't store 'version', as it is always 2
  // we don't store 'zero', as it is always 0
  RipEntry entries[RIP_MAX_ENTRY];
} RipPacket;
extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern vector<RoutingTableEntry> table;

//read addr from packet
extern uint32_t get_int32(const uint8_t *packet, int base_index, bool isBigEndian);
//write addr to packet`
extern void write_int32(uint8_t *packet, int index, uint32_t addr, bool isBigEndian);

//封装packet,返回packet字节数
int wrap_packet(uint8_t *output, uint32_t src_addr, uint32_t dst_addr, const RipPacket *rip)
{
  output[0] = 0x45;
  output[1] = 0;
  int ip_len = 32 + 20 * rip->numEntries;
  //Total Length
  output[2] = ip_len >> 8;
  output[3] = ip_len & 0xff;
  //Identifier
  output[4] = 0;
  output[5] = 0;
  //Flags/Offset
  output[6] = 0;
  output[7] = 0;
  //TTL
  output[8] = 2;
  //Protocal: UDP
  output[9] = 17;
  //checksum
  forward(output, ip_len);
  write_int32(output, 12, src_addr, true);
  write_int32(output, 16, dst_addr, true);
  // UDP
  // source port = 520
  output[20] = 0x02;
  output[21] = 0x08;
  //dest port = 520
  output[22] = 0x02;
  output[23] = 0x08;
  //length
  int udp_len = ip_len - 20;
  output[24] = udp_len >> 8;
  output[25] = udp_len & 0xff;
  //checksum(disabled)
  output[26] = 0;
  output[27] = 0;
  // RIP
  uint32_t rip_len = assemble(rip, &output[20 + 8]);
  return ip_len;
}

uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a,
                                     0x0103000a};

int main(int argc, char *argv[])
{
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0)
  {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++)
  {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0x00ffffff, // big endian
        .len = 24,                     // small endian
        .if_index = i,                 // small endian
        .nexthop = 0,                  // big endian, means direct
        .metric = 16                   //potential problem
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1)
  {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 30 * 1000)
    {
      // What to do?
      // send complete routing table to every interface
      RipPacket resp;
      // TODO: fill resp
      resp.numEntries = table.size();
      resp.command = 2; //response
      for (int i = 0; i < table.size(); i++)
      {
        uint32_t t_addr = table[i].addr;
        uint32_t t_mask = (0xffffffff >> (32 - table[i].len));
        resp.entries[i].addr = t_addr;
        resp.entries[i].mask = t_mask;
        resp.entries[i].nexthop = table[i].nexthop;
        resp.entries[i].metric = table[i].metric;
      }
      in_addr_t multicast_addr = 0x090000e0;
      macaddr_t multicast_mac = {0x01,0x00,0x5e,0x00,0x00,0x09};
      for (int i = 0; i < N_IFACE_ON_BOARD; i++)
      {
        int ip_len = wrap_packet(output, addrs[i], multicast_addr, &resp);
        HAL_SendIPPacket(i, output, ip_len, multicast_mac);
      }

      // ref. RFC2453 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
      printf("30s Timer\n");
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    if (res == HAL_ERR_EOF)
    {
      break;
    }
    else if (res < 0)
    {
      return res;
    }
    else if (res == 0)
    {
      // Timeout
      continue;
    }
    else if (res > sizeof(packet))
    {
      // packet is truncated, ignore it
      continue;
    }

    // 1. validate
    if (!validateIPChecksum(packet, res))
    {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr, src_port_addr;
    // extract src_addr and dst_addr from packet
    // big endian
    src_addr = get_int32(packet, 12, true);
    dst_addr = get_int32(packet, 16, true);
    src_port_addr = addrs[if_index];

    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++)
    {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0)
      {
        dst_is_me = true;
        break;
      }
    }
    // Handle rip multicast address(224.0.0.9)?
    in_addr_t multicast_addr = 0x090000e0;
    if (dst_addr == multicast_addr)
    {
      dst_is_me = true;
    }

    if (dst_is_me)
    {
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip))
      {
        if (rip.command == 1)
        {
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab
          if (rip.entries[0].metric != 16)
          {
            printf("request rip entry's metric is not 16, no response.\n");
            continue;
          }
          RipPacket resp;
          // TODO: fill resp
          resp.numEntries = table.size();
          resp.command = 2; //response
          for (int i = 0; i < table.size(); i++)
          {
            uint32_t t_addr = table[i].addr;
            uint32_t t_mask = (0xffffffff >> (32 - table[i].len));
            if ((t_addr & t_mask) == (src_addr & t_mask))
            {
              resp.numEntries--;
              continue;
            }
            resp.entries[i].addr = t_addr;
            resp.entries[i].mask = t_mask;
            resp.entries[i].nexthop = table[i].nexthop;
            resp.entries[i].metric = table[i].metric;
          }
          memcpy(output, packet, res);
          int ip_len = wrap_packet(output, src_port_addr, src_addr, &resp);

          // checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
          // send it back
          HAL_SendIPPacket(if_index, output, ip_len, src_mac);
        }
        else
        {
          // 3a.2 response, ref. RFC2453 3.9.2
          for (int i = 0; i < rip.numEntries; i++)
          {
            //potential problem: need to mask?
            uint32_t addr = rip.entries[i].addr;
            uint32_t len = 0, mask = rip.entries[i].mask;
            while (mask != 0)
            {
              mask >>= 1;
              len++;
            }
            RoutingTableEntry entry;
            entry.addr = addr;
            entry.len = len;
            entry.nexthop = src_addr;
            entry.if_index = if_index; //potential problem: what to assign?
            entry.metric = rip.entries[i].metric + 1;
            //query
            uint32_t nexthop, dest_if, metric;
            if (query(dst_addr, &nexthop, &dest_if, &metric))
            {
              //found
              entry.if_index = dest_if;
              if (entry.metric > 16)
              {
                update(false, entry); //delete
                printf("delete route:\n");
                printf("\taddr: %d\n\tlen: %d\n\tnexthop: %d\n\tif_index: %d\n\tmetric: %d\n", entry.addr, entry.len, entry.nexthop, entry.if_index, entry.metric);
              }
              else
              {
                update(true, entry);
                printf("update route:\n");
                printf("\taddr: %d\n\tlen: %d\n\tnexthop: %d\n\tif_index: %d\n\tmetric: %d\n", entry.addr, entry.len, entry.nexthop, entry.if_index, entry.metric);
              }
            }
            else
            {
              //not found
              update(true, entry);
              printf("insert route:\n");
              printf("\taddr: %d\n\tlen: %d\n\tnexthop: %d\n\tif_index: %d\n\tmetric: %d\n", entry.addr, entry.len, entry.nexthop, entry.if_index, entry.metric);
            }
          }

          // update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // what is missing from RoutingTableEntry?
          // TODO: use query and update
          // triggered updates? ref. RFC2453 3.10.1
        }
      }
    }
    else
    {
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if;
      if (query(dst_addr, &nexthop, &dest_if))
      {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0)
        {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0)
        {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          forward(output, res);
          // TODO: you might want to check ttl=0 case
          HAL_SendIPPacket(dest_if, output, res, dest_mac);
        }
        else
        {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      }
      else
      {
        // not found
        // optionally you can send ICMP Host Unreachable
        printf("IP not found for %x\n", src_addr);
      }
    }
  }
  return 0;
}
