package main

import "core:sys/win32"
import "core:strings"
import "core:fmt"

import w32 "win32-winmd"

main :: proc() {
	state := w32.XINPUT_STATE{};
	// ok := w32.BOOL;
	w32.XInputEnable(true);
	res := w32.XInputGetState(0, &state);
	fmt.println(res);
	fmt.println(state);
}

