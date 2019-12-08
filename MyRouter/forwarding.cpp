#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
uint16_t getchecksum(uint8_t *packet, size_t len);
 
bool forward(uint8_t *packet, size_t len) {
	if(getchecksum(packet, len) != 0)
		return false;
	packet[8]--;
	packet[10] = packet[11] = 0;
	uint16_t sum = getchecksum(packet, len);
    packet[10] = sum >> 8;
    packet[11] = sum & 0xff;
	return true;
}

uint16_t getchecksum(uint8_t *packet, size_t len) {
  uint32_t ihl = packet[0] & 0x0f;
  uint32_t checksum = 0;
  uint32_t max_uint16 = 0xffff;
  
  uint32_t size = ihl << 2;  //ip头byte数
  for(uint32_t i=0; i<size; i+=2)
  {
	  checksum += packet[i] << 8;
	  checksum += packet[i+1];
  }
  while(checksum > max_uint16)
  {
	  uint32_t low_16 = checksum & max_uint16;
      uint32_t overflow = checksum >> 16;
	  checksum = low_16 + overflow;
  }
  //checksum = ~checksum;
  //packet[10] = checksum >> 8;
  //packet[11] = checksum & 0xff;
  return ~(uint16_t)checksum;
}