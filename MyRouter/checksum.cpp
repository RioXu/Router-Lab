#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
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
  return (checksum == 0xffff);
}
