#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(response) and 0(request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/
uint32_t BigLittleSwap32(uint32_t a)
{
	uint32_t b = (a & 0xff000000) >> 24;
	b |= (a & 0xff0000) >> 8;
	b |= (a & 0xff00) << 8;
	b |= (a & 0xff) << 24;
	return b;
}

bool check_mask(uint32_t mask)
{
	int num_change = 0;
	int last_digit = mask & 1;
	int init_last_digit = last_digit;
	for (int i = 1; i < 32; i++)
	{
		int digit = (mask >> i) & 1;
		if (digit != last_digit)
			num_change++;
		last_digit = digit;
	}
	if (init_last_digit == 0 && num_change > 1)
		return false;
	if (init_last_digit == 1 && num_change > 0)
		return false;
	return true;
}

void write_int32(uint8_t *packet, int index, uint32_t addr, bool isBigEndian)
{
	if (!isBigEndian)
		addr = BigLittleSwap32(addr);
	packet[index] = addr & 0xff;
	packet[index + 1] = (addr >> 8) & 0xff;
	packet[index + 2] = (addr >> 16) & 0xff;
	packet[index + 3] = (addr >> 24) & 0xff;
}

uint32_t get_int32(const uint8_t *packet, int base_index, bool isBigEndian)
{
	uint32_t digit1 = packet[base_index];
	uint32_t digit2 = packet[base_index + 1];
	uint32_t digit3 = packet[base_index + 2];
	uint32_t digit4 = packet[base_index + 3];
	if (isBigEndian) //big endian
		return (digit4 << 24) + (digit3 << 16) + (digit2 << 8) + digit1;
	else
	{
		return (digit1 << 24) + (digit2 << 16) + (digit3 << 8) + digit4;
	}
}

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output)
{
	//判断合法性（此处不检查报文协议，默认UDP）
	uint16_t totlenth = (packet[2] << 8) + packet[3];
	if (totlenth > len)
		return false;
	uint8_t command = packet[28];
	if (command != 1 && command != 2)
		return false;
	uint8_t version = packet[29];
	if (version != 2)
		return false;
	uint16_t zero = (packet[30] << 8) + packet[31];
	if (zero != 0)
		return false;
	//开始解析
	//（ip长度-ip报头长度-udp报头长度-ripv2头部长度）/单条rip长度
	uint32_t numEntries = (len - 4 * (packet[0] & 0x0f) - 12) / 20;

	if (numEntries <= 0)
		return false;
	output->command = command;
	output->numEntries = numEntries;
	int index = 32;
	for (int i = 0; i < numEntries; i++)
	{
		uint16_t family = (packet[index] << 8) + packet[index + 1];
		bool correspond = (family == 0 && command == 1) || (family == 2 && command == 2);
		if (!correspond)
			return false;
		//判断route tag
		uint16_t route_tag = (packet[index + 2] << 8) + packet[index + 3];
		if (route_tag != 0)
			return false;
		uint32_t addr = get_int32(packet, index + 4, true);
		uint32_t mask = get_int32(packet, index + 8, false);
		if (!check_mask(mask))
			return false;
		mask = BigLittleSwap32(mask);
		uint32_t nexthop = get_int32(packet, index + 12, true);
		int metric = get_int32(packet, index + 16, false);
		if (metric < 1 || metric > 16)
			return false;
		metric = BigLittleSwap32(metric);
		output->entries[i].addr = addr;
		output->entries[i].mask = mask;
		output->entries[i].nexthop = nexthop;
		output->entries[i].metric = metric;
		index += 20;
	}
	return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer)
{
	//填充RIP头
	buffer[0] = rip->command;
	buffer[1] = 2;
	buffer[2] = buffer[3] = 0;

	//填充entries
	int index = 4;
	for (int i = 0; i < rip->numEntries; i++)
	{
		//family
		uint8_t family = rip->command == 1 ? 0 : 2;
		buffer[index] = 0;
		buffer[index + 1] = family;
		//route tag
		buffer[index + 2] = 0;
		buffer[index + 3] = 0;
		//addr
		uint32_t addr = rip->entries[i].addr;
		buffer[index + 4] = addr & 0xff;
		buffer[index + 5] = (addr >> 8) & 0xff;
		buffer[index + 6] = (addr >> 16) & 0xff;
		buffer[index + 7] = (addr >> 24) & 0xff;
		//mask
		uint32_t mask = rip->entries[i].mask;
		buffer[index + 8] = mask & 0xff;
		buffer[index + 9] = (mask >> 8) & 0xff;
		buffer[index + 10] = (mask >> 16) & 0xff;
		buffer[index + 11] = (mask >> 24) & 0xff;
		//nexthop
		uint32_t nexthop = rip->entries[i].nexthop;
		buffer[index + 12] = nexthop & 0xff;
		buffer[index + 13] = (nexthop >> 8) & 0xff;
		buffer[index + 14] = (nexthop >> 16) & 0xff;
		buffer[index + 15] = (nexthop >> 24) & 0xff;
		//metric
		uint32_t metric = rip->entries[i].metric;
		buffer[index + 16] = metric & 0xff;
		buffer[index + 17] = (metric >> 8) & 0xff;
		buffer[index + 18] = (metric >> 16) & 0xff;
		buffer[index + 19] = (metric >> 24) & 0xff;
		index += 20;
	}
	return index;
}
