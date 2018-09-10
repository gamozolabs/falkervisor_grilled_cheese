#pragma once

rstate_t
ide_pio_read_sectors(
		_In_ uint64_t                        lba,
		_Out_writes_bytes_all_(512) uint8_t *buf,
		_In_ size_t                          buf_len);

