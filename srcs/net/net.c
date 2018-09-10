#include <grilled_cheese.h>
#include <disp/disp.h>
#include <mm/mm.h>
#include <net/net.h>
#include <net/x540.h>
#include <generic/stdlib.h>
#include <time/time.h>
#include <interrupts/interrupts.h>

static struct _net_device  net_devices     = { { 0 } };
static struct _net_device *net_devices_end = &net_devices;

static rstate_t
net_dhcp(struct _net_device *device, struct _net_queue *queue);

static rstate_t
net_probe_pci(void)
{
	uint32_t bus, func, dev, pci_addr, viddid;
	uint64_t bar0;
	
	RSTATE_LOCALS;

	for(bus = 0; bus < 0x100; bus++){
		for(dev = 0; dev < 0x20; dev++){
			for(func = 0; func < 0x8; func++){
				/* enable bit, bus, dev, func */
				pci_addr = (1 << 31) | \
						   (bus << 16) | (dev << 11) | (func << 8);

				/* Fetch the vid/did */
				outd(0xCF8, pci_addr);
				viddid = ind(0xCFC);

				/* Fetch the BAR0 */
				outd(0xCF8, pci_addr | 0x10);
				bar0 = (ind(0xCFC) & ~0xF);

				if(viddid == 0x15288086){
					uint64_t key;

					struct _net_device *device;

					/* Allocate room for a new net device */
					rstate = phalloc(sizeof(struct _net_device), (void**)&device);
					RSCHECK_NESTED("Failed to allocate room for net device");

					/* Unknown MAC and IP, zero them out */
					memset(device->mac, 0, 6);
					device->ip = 0;

					/* By default we don't know the DHCP MAC or IP, default
					 * to broadcast.
					 */
					memset(device->dhcp_mac, 0xff, 6);
					device->dhcp_ip         = 0xffffffff;
					device->dhcp_lease_time = 0;

					/* Map in the bar0 */
    				rstate = mm_reserve_random(readcr3(), 128 * 1024,
							(void*)&device->bar0, 0, &key);
					RSCHECK_NESTED("Failed to reserve random page for bar0");
					rstate = mm_map_contig(readcr3(),
							device->bar0,
							bar0 | 3 | (1UL << 63), 128 * 1024, key);
					RSCHECK_NESTED("Failed to map in bar0");

					/* Initialize the linked list */
					device->queues.next = NULL;
					device->queues_end  = &device->queues;
					device->next        = NULL;

					/* Reset and initialize the x540 device. This will also
					 * populate the mac address field in device.
					 */
					rstate = x540_init(device);
					RSCHECK_NESTED("Failed to initialize x540 device");

					{
						struct _net_queue *queue, *old_queue;

						/* Create queue 0 for this device */
						rstate = phalloc(sizeof(struct _net_queue), (void**)&queue);
						RSCHECK_NESTED("Failed to allocate queue for net device");

						/* Initialize the queue state */
						queue->queue_id = __sync_fetch_and_add(&device->num_queues, 1);
						queue->device   = device;
						queue->filter_port = htons(NET_BASE_PORT - 1);

						/* Initialize the first queue for this device */
						rstate = x540_queue_init(queue);
						RSCHECK_NESTED("Failed to initialize queue");

						/* Store this as the interrupt queue */
						device->interrupt_queue = queue;

						/* Add the queue to the device queue list */
						do {
							old_queue = device->queues_end;
						} while(!__sync_bool_compare_and_swap(&device->queues_end, old_queue, queue));
						old_queue->next = queue;
					}

					/* Get a DHCP lease for this device */
					rstate = net_dhcp(device, device->interrupt_queue);
					RSCHECK_NESTED("Failed to get DHCP lease");

					if(rstate == RSTATE_SUCCESS){
						/* Add this device to the global device list */
						net_devices_end->next = device;
						net_devices_end       = device;
					}
				}
			}
		}
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

rstate_t
net_init(void)
{
	RSTATE_LOCALS;

	rstate = net_probe_pci();
	RSCHECK_NESTED("Failed to probe PCI devices");

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

rstate_t
net_init_local_queue(void)
{
	struct _net_device *device;
	struct _net_queue  *queue, *old_queue;
	
	RSTATE_LOCALS;

	device = net_devices.next;
	if(!device){
		/* No network devices present, cannot create default queue */
		return RSTATE_SUCCESS;
	}

	/* Create queue 0 for this device */
	rstate = phalloc(sizeof(struct _net_queue), (void*)&queue);
	RSCHECK_NESTED("Failed to allocate queue for net device");

	/* Initialize the queue state */
	queue->queue_id    = __sync_fetch_and_add(&device->num_queues, 1);
	queue->filter_port = htons(NET_BASE_PORT + current_cpu->cpu_id);
	queue->device      = device;

	/* Initialize the first queue for this device */
	rstate = x540_queue_init(queue);
	RSCHECK_NESTED("Failed to initialize queue");

	/* Add the queue to the device queue list */
	do {
		old_queue = device->queues_end;
	} while(!__sync_bool_compare_and_swap(&device->queues_end, old_queue, queue));
	old_queue->next = queue;

	/* Assign this as the default network queue for this CPU */
	current_cpu->net_queue = queue;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

void
net_display_devices(void)
{
	int id = 0;

	struct _net_device *device;

	device = net_devices.next;
	if(!device){
		printf("No network devices present");
		return;
	}

	while(device){
		uint32_t server_ip = htonl(device->dhcp_ip);
		uint32_t client_ip = htonl(device->ip);

		printf("Network Device #%d", id);

		printf(
				"    Client:     %u.%u.%u.%u (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x)\n"
				"    Server:     %u.%u.%u.%u (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x)\n"
				"    Lease time: %u days (%u seconds)",
				(client_ip >> 24) & 0xff,
				(client_ip >> 16) & 0xff,
				(client_ip >>  8) & 0xff,
				(client_ip >>  0) & 0xff,
				device->mac[0], device->mac[1], device->mac[2],
				device->mac[3], device->mac[4], device->mac[5],

				(server_ip >> 24) & 0xff,
				(server_ip >> 16) & 0xff,
				(server_ip >>  8) & 0xff,
				(server_ip >>  0) & 0xff,
				device->dhcp_mac[0], device->dhcp_mac[1], device->dhcp_mac[2],
				device->dhcp_mac[3], device->dhcp_mac[4], device->dhcp_mac[5],

				device->dhcp_lease_time / (3600 * 24),
				device->dhcp_lease_time);

		device = device->next;
		id++;
	}

	return;
}

rstate_t
net_process_interval(void)
{
	struct _net_device *device;

	RSTATE_LOCALS;

	device = net_devices.next;
	while(device){
		struct _net_queue *queue = device->interrupt_queue;

		RSCHECK(queue, "No interrupt queue present");

		rstate = net_start(queue);
		RSCHECK_NESTED("Failed to start networking");

		for( ; ; ){
			uint8_t  *packet;
			uint32_t  packet_len;

			rstate = queue->recv(queue, (void**)&packet, &packet_len);
			RSCHECK_NESTED("Failed to recv raw packets from queue");

			if(!packet){
				break;
			}

			rstate = net_consume_unwanted(device, packet, packet_len);
			RSCHECK_NESTED("Failed to consume unwanted packet");

			net_recv_release(queue);
		}

		net_stop(queue);

		device = device->next;
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

rstate_t
net_consume_unwanted(struct _net_device *device,
		uint8_t *packet, uint32_t packet_len)
{
	struct _net_queue *queue = device->interrupt_queue;
	uint8_t  *udp_packet;
	uint32_t  udp_packet_len;

	struct _arp_packet *arp_packet;
	
	RSTATE_LOCALS;

	arp_packet = (struct _arp_packet*)packet;

	if(packet_len >= sizeof(struct _arp_packet) &&
			arp_packet->type == htons(0x0806) &&
			arp_packet->hw_type == htons(0x0001) &&
			arp_packet->proto_type == htons(0x0800) &&
			arp_packet->hw_size == 6 &&
			arp_packet->proto_size == 4 &&
			arp_packet->op == htons(1) &&
			arp_packet->target_ip == device->ip){

		memcpy(arp_packet->dest_mac, arp_packet->sender_mac, 6);
		memcpy(arp_packet->src_mac, queue->device->mac, 6);
		arp_packet->op = htons(2);
		
		memcpy(arp_packet->target_mac, arp_packet->sender_mac, 6);
		arp_packet->target_ip = arp_packet->sender_ip;

		memcpy(arp_packet->sender_mac, queue->device->mac, 6);
		arp_packet->sender_ip = device->ip;

		rstate = queue->send(queue, arp_packet, sizeof(struct _arp_packet));
		RSCHECK_NESTED("Failed to send ARP response");
	} else if(net_parse_udp(packet, packet_len,
				(void**)&udp_packet, &udp_packet_len) == RSTATE_SUCCESS){

		if(udp_packet_len == 8 &&
				*(uint64_t*)udp_packet == NET_REBOOT_REQUEST){
			request_soft_reboot(device);
		}
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

rstate_t
net_send_udp(
		struct _net_queue *queue,
		const void        *payload,
		uint32_t           len,
		uint32_t           dest_ip,
		uint32_t           dest_port)
{
	struct _net_device *device = queue->device;
	struct _udp_packet  packet = { { 0 } };

	RSTATE_LOCALS;

	RSCHECK(len <= sizeof(packet.payload),
			"Payload is too large for IP packet");

	if(!dest_ip)   dest_ip   = device->dhcp_ip;
	if(!dest_port) dest_port = queue->filter_port;

	/* MAC header */
	memcpy(packet.dest_mac, device->dhcp_mac, 6);
	memcpy(packet.src_mac,  device->mac, 6);
	packet.type = htons(0x0800); /* IP packet */

	/* IP header */
	packet.ver     = 0x45;
	packet.svc     = 0;
	packet.len     = htons(28 + len);
	packet.ident   = 0;
	packet.flags   = 0;
	packet.frag    = 0;
	packet.ttl     = 0x80;
	packet.proto   = 0x11; /* UDP */
	packet.ip_chk  = 0;
	packet.src_ip  = device->ip;
	packet.dest_ip = dest_ip;

	/* UDP header */
	packet.src_port  = queue->filter_port;
	packet.dest_port = dest_port;
	packet.ulen      = htons(8 + len);
	packet.udp_chk   = 0;

	/* Copy in the payload */
	memcpy(packet.payload, payload, len);

	/* Compute the checksum */
	{
		int i;

		uint16_t *ptr;
		uint64_t  sum = 0;

		ptr = (uint16_t*)&packet.ver;

		for(i = 0; i < 10; i++){
			sum += ntohs(ptr[i]);
		}

		sum = ~(sum + (sum >> 16));

		packet.ip_chk = htons(sum);
	}

	/* Send the packet */
	rstate = queue->send(queue, &packet,
			(uint32_t)offsetof(struct _udp_packet, payload) + len);
	RSCHECK_NESTED("Failed to send UDP packet");

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

rstate_t
net_parse_udp(
		const void  *packet,
		uint32_t     packet_len,
		void       **udp_payload,
		uint32_t    *udp_payload_len)
{
	uint32_t udp_len;
	struct _udp_packet *udp;

	RSTATE_LOCALS;

	/* Check if the packet is large enough to be a UDP packet */
	RSCHECK(packet_len >= 42, "Packet was too small to be UDP");

	udp = (struct _udp_packet*)packet;

	/* Make sure the packet is IPv4, IP and UDP */
	RSCHECK(udp->ver == 0x45 && udp->type == 8 && udp->proto == 0x11,
			"Packet was not UDP");

	udp_len = ntohs(udp->ulen);

	/* Make sure the udp length is within bounds */
	RSCHECK(udp_len >= 8 && (udp_len + 42 - 8) <= packet_len,
			"Out of bounds error on UDP packet");

	*udp_payload     = udp->payload;
	*udp_payload_len = udp_len - 8;
	
	rstate_ret = rstate = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

rstate_t
net_recv_udp(
		struct _net_queue   *queue,
		void               **packet,
		uint32_t            *packet_len,
		struct _udp_packet **raw)
{
	void     *tmp;
	uint32_t tmp_len;

	RSTATE_LOCALS;

	/* Grab a raw packet */
	rstate = queue->recv(queue, &tmp, &tmp_len);
	RSCHECK_NESTED("Failed to recv packet");

	if(!tmp){
		*packet      = NULL;
		*packet_len  = 0;
		if(raw) *raw = NULL;
		return RSTATE_SUCCESS;
	}
	
	if(net_parse_udp(tmp, tmp_len, packet, packet_len) != RSTATE_SUCCESS){
		if(queue == queue->device->interrupt_queue){
			rstate = net_consume_unwanted(queue->device, tmp, tmp_len);
			RSCHECK_NESTED("Failed to consume unwanted packet");
		}

		net_recv_release(queue);

		*packet      = NULL;
		*packet_len  = 0;
		if(raw) *raw = NULL;
		return RSTATE_SUCCESS;
	}

	/* Return out the raw pointer */
	if(raw) *raw = tmp;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

rstate_t
net_recv_release(struct _net_queue *queue)
{
	RSTATE_LOCALS;

	rstate = queue->recv_release(queue);
	RSCHECK_NESTED("Failed to release recv buffer");

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

static rstate_t
net_dhcp(struct _net_device *device, struct _net_queue *queue)
{
#pragma pack(push, 1)
	struct _dhcp_packet {
		uint8_t  op;
		uint8_t  htype;
		uint8_t  hlen;
		uint8_t  hops;
		uint32_t xid;
		uint16_t elapsed;
		uint16_t dhcp_flags;
		uint32_t ciaddr;
		uint32_t yiaddr;
		uint32_t siaddr;
		uint32_t giaddr;
		uint8_t  chaddr[16];
		uint8_t  sname[64];
		uint8_t  file[128];
		uint32_t magic;

		union {
			struct {
				uint8_t discover[4];
			} disc;

			struct {
				uint8_t type[3];
				uint8_t mac[9];
				uint8_t ip[6];
				uint8_t server[6];
				uint8_t end;
			} request;

			uint8_t options[256];
		} u;
	} dhcp_packet = { 0 };
#pragma pack(pop)

	uint8_t  server_mac[6];
	uint32_t lease_time = 0, server_ip = 0, client_ip = 0, retries = 3;
	uint64_t timeout;

	RSTATE_LOCALS;

	rstate = net_start(queue);
	RSCHECK_NESTED("Failed to start networking for queue");

retry_dhcp:
	RSCHECK(retries, "Failed to get DHCP lease, out of retries");
	retries--;

	dhcp_packet.op    = 1; /* boot request */
	dhcp_packet.htype = 1; /* ethernet device */
	dhcp_packet.hlen  = 6; /* hardware length (6 for a MAC address) */
	dhcp_packet.xid   = __rdtsc() & 0xffffffff; /* transaction ID */
	memcpy(dhcp_packet.chaddr, queue->device->mac, 6);
	dhcp_packet.magic = 0x63538263;

	/* DHCP discover message */
	memset(dhcp_packet.u.options, 0, sizeof(dhcp_packet.u.options));
	memcpy(dhcp_packet.u.disc.discover, "\x35\x01\x01\xff", 4);
	
	rstate = net_send_udp(queue, &dhcp_packet, sizeof(dhcp_packet), 0, htons(67));
	RSCHECK_NESTED("Failed to send DHCP discover");

	timeout = rdtsc_future(5000000);

	for( ; ; ){
		uint8_t  *options;
		uint32_t  offer_len, options_len;

		struct _dhcp_packet *dhcp_offer;
		struct _udp_packet  *raw;

		if(__rdtsc() > timeout){
			goto retry_dhcp;
		}

		rstate = net_recv_udp(queue, (void**)&dhcp_offer, &offer_len, &raw);
		RSCHECK_NESTED("Failed to recv DHCP offer");
		if(!dhcp_offer) continue;

		if(offer_len < offsetof(struct _dhcp_packet, u) ||
				dhcp_offer->magic != 0x63538263 ||
				dhcp_offer->xid != dhcp_packet.xid){
			net_recv_release(queue);
			continue;
		}

		server_ip = dhcp_offer->siaddr;
		client_ip = dhcp_offer->yiaddr;

		options     = (uint8_t*)&dhcp_offer->u.options;
		options_len = offer_len - offsetof(struct _dhcp_packet, u);

		RSCHECK(options_len >= 3 && !memcmp(options, "\x35\x01\x02", 3),
			"Got response to DHCP discover which was not an offer");

		RSCHECK(server_ip == raw->src_ip,
			"Offer server IP did not match sender IP");

		/* Save off the DHCP server MAC */
		memcpy(server_mac, raw->src_mac, 6);

		net_recv_release(queue);
		break;
	}

	/* Construct a DHCP request */
	dhcp_packet.hlen = 6; /* hardware length (6 for a MAC address) */
	dhcp_packet.xid  = __rdtsc() & 0xffffffff; /* transaction ID */

	memset(dhcp_packet.u.options, 0, 256);
	memcpy(dhcp_packet.u.request.type, "\x35\x01\x03", 3);
	memcpy(dhcp_packet.u.request.mac, "\x3d\x07\x01", 3);
	memcpy(dhcp_packet.u.request.mac + 3, queue->device->mac, 6);
	memcpy(dhcp_packet.u.request.ip, "\x32\x04", 2);
	memcpy(dhcp_packet.u.request.ip + 2, &client_ip, 4);
	memcpy(dhcp_packet.u.request.server, "\x36\x04", 2);
	memcpy(dhcp_packet.u.request.server + 2, &server_ip, 4);
	dhcp_packet.u.request.end = 0xff;

	rstate = net_send_udp(queue, &dhcp_packet, sizeof(dhcp_packet), 0, htons(67));
	RSCHECK_NESTED("Failed to send DHCP request");

	timeout = rdtsc_future(5000000);

	for( ; ; ){
		uint8_t  *options;
		uint32_t  ack_len, options_len;

		struct _dhcp_packet *dhcp_ack;
		struct _udp_packet  *raw;

		if(__rdtsc() > timeout){
			goto retry_dhcp;
		}

		rstate = net_recv_udp(queue, (void**)&dhcp_ack, &ack_len, &raw);
		RSCHECK_NESTED("Failed to recv DHCP ack");
		if(!dhcp_ack) continue;

		if(ack_len < offsetof(struct _dhcp_packet, u) ||
				dhcp_ack->magic != 0x63538263 ||
				dhcp_ack->xid != dhcp_packet.xid){
			net_recv_release(queue);
			continue;
		}

		options     = (uint8_t*)&dhcp_ack->u.options;
		options_len = ack_len - offsetof(struct _dhcp_packet, u);

		RSCHECK(options_len >= 3 && !memcmp(options, "\x35\x01\x05", 3),
			"Got response to DHCP request which was not an ACK");
		
		RSCHECK(dhcp_ack->yiaddr == client_ip,
			"DHCP ACK was of different address than request");

		while(options_len){
			uint8_t option, len;

			/* Grab the option ID */
			option = *options++;
			options_len--;

			if(option == 0xff) break;
			RSCHECK(options_len != 0,
					"Invalid formatted DHCP option");

			/* Grab the option length */
			len = *options++;
			options_len--;

			RSCHECK(len <= options_len, "DHCP option OOB");

			if(option == 51 && len >= 4){
				lease_time = htonl(*(uint32_t*)options);
			}

			options     += len;
			options_len -= len;
		}

		net_recv_release(queue);
		break;
	}

	/* Slight sanity check */
	RSCHECK(server_ip && client_ip,
			"Either server IP or client IP was 0.0.0.0");

	RSCHECK((lease_time / (3600 * 24)) >= 365,
			"DHCP lease time was less than a year");

	/* Save our DHCP information */
	memcpy(device->dhcp_mac, server_mac, 6);
	device->dhcp_ip         = server_ip;
	device->ip              = client_ip;
	device->dhcp_lease_time = lease_time;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	net_stop(queue);
	RSTATE_RETURN;
}

rstate_t
net_notify_server(void)
{
	struct _notify_server {
		uint64_t magic;
		uint64_t req_id;
	} notify_server;
	
	RSTATE_LOCALS;

	if(!current_cpu->net_queue){
		return RSTATE_SUCCESS;
	}

	rstate = net_start(current_cpu->net_queue);
	RSCHECK_NESTED("Failed to start networking");

	notify_server.magic  = NET_NOTIFY_REBOOT;
	notify_server.req_id = aes_rand();

	rstate = net_send_udp(current_cpu->net_queue, &notify_server,
			sizeof(notify_server), 0, 0);
	RSCHECK_NESTED("Failed to send notification packet");

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	net_stop(current_cpu->net_queue);
	RSTATE_RETURN;
}

rstate_t
net_download_file(
		struct _net_queue  *queue,
		const char         *filename,
		uint64_t            offset,
		void              **outbuf,
		uint64_t           *outlen)
{
	uint8_t *buf = NULL, *ptr;

	int      retries = 128, prealc = 0;
	uint64_t fn_len, file_len, file_rem, timeout, seq_id;

	struct _file_download download = { 0 };
	
	RSTATE_LOCALS;

	fn_len = strlen(filename);

	RSCHECK(fn_len && fn_len < sizeof(download.fn), "Invalid filename");

	rstate = net_start(queue);
	RSCHECK_NESTED("Failed to start networking");

	if(*outbuf != NULL){
		prealc = 1;
	}

retry:
	RSCHECK(retries, "Out of retries, download failed");
	retries--;

	/* Free any existing buffer */
	if(!prealc && buf){
		rstate = phfree(buf, file_len);
		RSCHECK_NESTED("Failed to free download buffer");
		buf = NULL;
	}

	download.magic     = NET_FILE_DOWNLOAD;
	download.req_id    = aes_rand();
	download.offset    = offset;
	download.info_only = 0;

	if(prealc){
		download.size = *outlen;
	} else {
		download.size = -1;
	}

	memcpy(download.fn, filename, fn_len + 1);

	rstate = net_send_udp(queue, &download, sizeof(download), 0, 0);
	RSCHECK_NESTED("Failed to send download request");

	timeout = rdtsc_future(1000000);
	for( ; ; ){
		uint32_t packet_len;

		struct _file_download_response *download_response;

		if(__rdtsc() > timeout){
			goto retry;
		}

		rstate = net_recv_udp(queue, (void**)&download_response,
				&packet_len, NULL);
		RSCHECK_NESTED("Failed to get response packet");

		/* If we got no packet, try again */
		if(!download_response){
			continue;
		}

		/* Check if this is the packet we're expecting */
		if(packet_len != sizeof(*download_response) ||
				download_response->magic != NET_FILE_DOWNLOAD_RESP ||
				download_response->req_id != download.req_id){
			net_recv_release(queue);
			continue;
		}

		RSCHECK(download_response->file_len != -1,
				"Server reported error. Perhaps the file does not exist?");

		file_len = download_response->file_len;
		net_recv_release(queue);
		break;
	}

	if(!prealc){
		/* Allocate a new buffer */
		rstate = phalloc(file_len, (void**)&buf);
		RSCHECK_NESTED("Failed to allocate room for downloaded file");
	} else {
		buf      = *outbuf;
		file_len = MIN(file_len, *outlen);
	}

	ptr      = buf;
	file_rem = file_len;
	seq_id   = 0;

	timeout = rdtsc_future(1000000);
	for( ; ; ){
		uint32_t packet_len;
		uint64_t expected_chunk;

		struct _file_download_chunk *download_chunk;

		if(__rdtsc() > timeout){
			goto retry;
		}

		rstate = net_recv_udp(queue, (void**)&download_chunk,
				&packet_len, NULL);
		RSCHECK_NESTED("Failed to get response packet");

		/* If we got no packet, try again */
		if(!download_chunk){
			continue;
		}

		expected_chunk = MIN(file_rem, NET_FILE_CHUNK_SIZE);

		/* Check if this is the packet we're expecting */
		if(download_chunk->magic != NET_FILE_DOWNLOAD_CHUNK ||
				download_chunk->req_id != download.req_id){
			net_recv_release(queue);
			continue;
		}

		if(download_chunk->seq_id != seq_id){
			net_recv_release(queue);
			continue;
		}

		if(packet_len !=
				offsetof(struct _file_download_chunk, buf) + expected_chunk){
			net_recv_release(queue);
			continue;
		}

		/* Update the sequence ID we expect next */
		seq_id++;
		
		/* Reset the timeout each time we get a packet */
		timeout = rdtsc_future(1000000);

		/* Save off the contents of the file */
		memcpy(ptr, download_chunk->buf, expected_chunk);

		/* Release the packet */
		net_recv_release(queue);

		ptr      += expected_chunk;
		file_rem -= expected_chunk;

		if(!file_rem){
			break;
		}
	}

	/* Return out the file */
	*outbuf = buf;
	*outlen = file_len;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	if(rstate_ret != RSTATE_SUCCESS && buf){
		if(!prealc){
			rstate = phfree(buf, file_len);
			RSCHECK_NESTED("Failed to free download buffer");
		}
	}
	net_stop(queue);
	RSTATE_RETURN;
}

static rstate_t
net_remote_map_pf_handler(
		struct _mm_key *key,
		void           *param,
		uintptr_t       fault_addr,
		int             read_req,
		int             write_req,
		int             exec_req)
{
	void      *virt_mapping;
	uint64_t   chunk, offset, bread, page, entry;
	uintptr_t  phys_page;
	struct _remote_map_state *rms = param;
	
	RSTATE_LOCALS;

	mm_acquire_paging_lock();

	RSCHECK(exec_req == 0, "Attempted to execute remote mapping");

	mm_get_phys_nolock(readcr3(), fault_addr, &entry);
	if(entry != key->key){
		rstate_ret = RSTATE_SUCCESS;
		goto cleanup;
	}

	chunk      = fault_addr - key->base_addr;
	chunk      = (chunk / rms->chunk_size) * rms->chunk_size;
	fault_addr = key->base_addr + chunk;

	/* Make sure this faulting address is in bounds */
	RSCHECK(contains(fault_addr, fault_addr+rms->chunk_size-1,
				key->base_addr, key->base_addr + key->length - 1),
		"Key match but out of bounds");

	offset = fault_addr - key->base_addr;

	/* Download the backing memory */
	bread = MIN(key->length - offset, rms->chunk_size);
	rstate = net_download_file(current_cpu->net_queue, rms->fn, offset,
			&rms->chunk_tmp, &bread);
	RSCHECK_NESTED("Failed to download file chunk for remote mapping");

	for(page = 0; page < rms->chunk_size; page += 4096){
		/* Allocate a backing page */
		rstate = alloc_phys_4k(&phys_page);
		RSCHECK_NESTED("Failed to allocate backing page for lazy allocation");

		/* Copy the read backing to physical memory. We must do this here
		 * because once we commit the page to memory other threads may
		 * access it. Doing the copy after the commit leads to a possible
		 * race of other threads reading incorrect memory!
		 */
		virt_mapping = mm_get_phys_mapping((uint64_t)phys_page);
		memcpy(virt_mapping, (uint8_t*)rms->chunk_tmp + page, 4096);
		mm_release_phys_mapping(virt_mapping);

		/* Commit the backing page */
		rstate = mm_map_4k_nolock(readcr3(), fault_addr + page,
					(uint64_t)phys_page | 7 | (1UL << 63),
					key->key);
		RSCHECK_NESTED("Failed to commit backing page for allocation");
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	mm_release_paging_lock();
	RSTATE_RETURN;
}

rstate_t
net_map_remote(
		struct _net_queue  *queue,
		const char         *filename,
		uint64_t            chunk_size,
		void               **outbuf,
		uint64_t            *outlen)
{
	uint8_t *buf = NULL;

	int      retries = 3;
	uint64_t fn_len, timeout, file_len, reserved, map_key;
	struct _file_download download;
	
	RSTATE_LOCALS;

	fn_len = strlen(filename);

	RSCHECK(fn_len && fn_len < sizeof(download.fn), "Invalid filename");

	rstate = net_start(queue);
	RSCHECK_NESTED("Failed to start networking");

	if(!chunk_size) chunk_size = 4096;
	chunk_size = (chunk_size + 0xfff) & ~0xfff;

retry:
	RSCHECK(retries, "Out of retries, download failed");
	retries--;

	download.magic     = NET_FILE_DOWNLOAD;
	download.req_id    = aes_rand();
	download.offset    = 0;
	download.size      = -1;
	download.info_only = 1;
	memcpy(download.fn, filename, fn_len + 1);

	rstate = net_send_udp(queue, &download, sizeof(download), 0, 0);
	RSCHECK_NESTED("Failed to send download request");

	timeout = rdtsc_future(10000000);
	for( ; ; ){
		uint32_t packet_len;

		struct _file_download_response *download_response;

		if(__rdtsc() > timeout){
			goto retry;
		}

		rstate = net_recv_udp(queue, (void**)&download_response,
				&packet_len, NULL);
		RSCHECK_NESTED("Failed to get response packet");

		/* If we got no packet, try again */
		if(!download_response){
			continue;
		}

		/* Check if this is the packet we're expecting */
		if(packet_len != sizeof(*download_response) ||
				download_response->magic != NET_FILE_DOWNLOAD_RESP ||
				download_response->req_id != download.req_id){
			net_recv_release(queue);
			continue;
		}

		RSCHECK(download_response->file_len != -1,
				"Server reported error. Perhaps the file does not exist?");

		file_len = download_response->file_len;
		net_recv_release(queue);
		break;
	}

	reserved = ((file_len + chunk_size - 1) / chunk_size) * chunk_size;

	rstate = mm_reserve_random(readcr3(), reserved, (void*)&buf,
			0, &map_key);
	RSCHECK_NESTED("Failed to reserve memory for remote mapping");

	{
		struct _mm_key *key;
		struct _remote_map_state *rms;

		rstate = phalloc(sizeof(struct _mm_key), (void**)&key);
		RSCHECK_NESTED("Failed to allocate room for mm key");
		
		rstate = phalloc(sizeof(struct _remote_map_state), (void**)&rms);
		RSCHECK_NESTED("Failed to allocate room for remote map state");

		rms->chunk_size = chunk_size;
		memcpy(rms->fn, filename, fn_len + 1);

		rstate = phalloc(chunk_size, &rms->chunk_tmp);
		RSCHECK_NESTED("Failed to allocate room for chunk_tmp");

		key->base_addr  = (uint64_t)buf;
		key->length     = reserved;
		key->key        = map_key;
		key->pf_handler = net_remote_map_pf_handler;
		key->param      = rms;

		mm_register_key_handler(key);
	}

	/* Return out the file */
	*outbuf = buf;
	*outlen = file_len;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	if(rstate_ret != RSTATE_SUCCESS && buf){
		rstate = phfree(buf, file_len);
		RSCHECK_NESTED("Failed to free download buffer");
	}

	net_stop(queue);
	RSTATE_RETURN;
}

rstate_t
net_start(struct _net_queue *queue)
{
	RSTATE_LOCALS;

	/* Attempt to grab a network queue for use by this task */
	RSCHECK(__sync_val_compare_and_swap(&queue->task_using,
				NULL, current_cpu->task) == NULL,
			"Network queue already in use");

	rstate_ret = rstate = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

void
net_stop(struct _net_queue *queue)
{
	/* Stop using this queue by replacing task_using with NULL. We panic
	 * here instead of RSTATE, such that we can use net_stop() in a cleanup
	 * case of another failed rstate.
	 */
	if(__sync_val_compare_and_swap(&queue->task_using,
				current_cpu->task, NULL) != current_cpu->task){
		panic("Attempted net_stop() on queue owned by another task");
	}
}

rstate_t
net_upload(
		struct _net_queue *queue,
		const char        *fn,
		void              *buf,
		size_t             len)
{
	int net_started = 0, retries = -1;
	size_t sent, fnlen;
	uint64_t timeout;
	struct _snap_upload upload;

	RSTATE_LOCALS;

	if(!len){
		return RSTATE_SUCCESS;
	}

	fnlen = strlen(fn);
	RSCHECK(fnlen && fnlen < sizeof(upload.fn),
			"Filename not present or too large");

	rstate = net_start(queue);
	RSCHECK_NESTED("Failed to start networking");
	net_started = 1;

resend:
	retries++;
	sent = 0;

	upload.magic    = 0x1A8FA024;
	upload.req_id   = aes_rand();
	upload.file_len = len;
	memcpy(upload.fn, fn, fnlen + 1);
	upload.hash     = falkhash(buf, len);
	rstate = net_send_udp(queue, &upload, sizeof(upload), 0, 0);
	RSCHECK_NESTED("Failed to send upload header");

	while(sent != len){
		size_t to_send = MIN(NET_FILE_CHUNK_SIZE, len-sent);
		struct _snap_upload_data data;

		data.magic  = NET_SNAP_UPLOAD_DATA;
		data.req_id = upload.req_id;
		memcpy(data.data, (uint8_t*)buf + sent, to_send);
		rstate = net_send_udp(queue, &data,
				(uint32_t)offsetof(struct _snap_upload_data, data) + to_send,
				0, 0);
		RSCHECK_NESTED("Failed to send upload payload");

		/* Target 50MB/s */
		rdtsc_sleep(156);

		sent += to_send;
	}

	timeout = rdtsc_future(1000000);
	for( ; ; ){
		struct _snap_upload_conf *conf;
		uint32_t conf_size;

		if(__rdtsc() >= timeout){
			goto resend;
		}

		rstate = net_recv_udp(queue, (void**)&conf, &conf_size, NULL);
		RSCHECK_NESTED("Failed to recv confirmation packet");

		if(!conf){
			continue;
		}

		if(conf_size != sizeof(struct _snap_upload_conf) ||
				conf->magic != NET_SNAP_UPLOAD_CONF ||
				conf->req_id != upload.req_id){
			net_recv_release(queue);
			continue;
		}

		net_recv_release(queue);
		break;
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	if(net_started) net_stop(queue);
	RSTATE_RETURN;
}

