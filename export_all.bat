winmd_parser.exe Windows.Win32.Direct3DDxgi dgxi > win32-winmd\dxgi.odin
winmd_parser.exe Windows.Win32.Direct3D10 d3d10 > win32-winmd\d3d10.odin
winmd_parser.exe Windows.Win32.Direct3D11 d3d11 > win32-winmd\d3d11.odin
winmd_parser.exe Windows.Win32.Direct3D12 d3d12 > win32-winmd\d3d12.odin
winmd_parser.exe Windows.Win32.Direct3DHlsl d3dcompiler > win32-winmd\hlsl.odin
winmd_parser.exe Windows.Win32.Gdi Gdi32 -skip_global_functions > win32-winmd\gdi.odin
winmd_parser.exe Windows.Win32.Http Httpapi > win32-winmd\http.odin
winmd_parser.exe Windows.Win32.MenuRc User32 -skip_global_functions > win32-winmd\menurc.odin
winmd_parser.exe Windows.Win32.XAudio2 xaudio2 > win32-winmd\xaudio2.odin
winmd_parser.exe Windows.Win32.XInput xinput > win32-winmd\xinput.odin
winmd_parser.exe Windows.Win32.WinSock Ws2_32 -skip_global_functions > win32-winmd\winsock.odin