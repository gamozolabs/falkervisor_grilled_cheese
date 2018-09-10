#pragma once

void
interrupts_enable(void);

void
interrupts_disable(void);

void
iret_stub(void);

uintptr_t
enter_um_guest(const struct _iret *iret, struct _iret *save,
		uint64_t *x86_regs);

void
profiling_dump(void);

void
request_soft_reboot(const void *dev);

void
pic_init(void);

rstate_t
interrupts_init(void);

