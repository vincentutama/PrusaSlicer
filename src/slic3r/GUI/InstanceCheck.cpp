#include "GUI_App.hpp"
#include "InstanceCheck.hpp"

//#include "Plater.hpp"

#include <boost/filesystem.hpp>
#include "boost/nowide/convert.hpp"
#include <boost/log/trivial.hpp>
#include <iostream>

#include <fcntl.h>
#include <errno.h>

#if _WIN32

//catching message from another instance
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
	TCHAR lpClassName[1000];
	GetClassName(hWnd, lpClassName, 100);
	switch (message)
	{
	case WM_COPYDATA:
	{
		COPYDATASTRUCT* copy_data_structure = { 0 };
		copy_data_structure = (COPYDATASTRUCT*)lParam;
		if(copy_data_structure->dwData == 1)
		{
			LPCWSTR arguments = (LPCWSTR)copy_data_structure->lpData;
			Slic3r::InstanceCheck::instance_check().handle_message(boost::nowide::narrow(arguments));
		}
		
	}
	break;
	}
	return DefWindowProc(hWnd, message, wParam, lParam);
}


BOOL CALLBACK EnumWindowsProc(_In_ HWND   hwnd, _In_ LPARAM lParam) {
	//checks for other instances of prusaslicer, if found brings it to front and return false to stop enumeration and quit this instance
	//search is done by classname(wxWindowNR is wxwidgets thing, so probably not unique) and name in window upper panel
	//other option would be do a mutex and check for its existence
	TCHAR wndText[1000];
	TCHAR className[1000];
	GetClassName(hwnd, className, 1000);
	GetWindowText(hwnd, wndText, 1000);
	std::wstring classNameString(className);
	std::wstring wndTextString(wndText);
	if (wndTextString.find(L"PrusaSlicer") != std::wstring::npos && classNameString == L"wxWindowNR") {
		std::wcout << L"found " << wndTextString << std::endl;
		ShowWindow(hwnd, SW_SHOWMAXIMIZED);
		SetForegroundWindow(hwnd);
		return false;
	}
	return true;
}

#endif //_WIN32 

namespace Slic3r {

#if _WIN32  ////////////////////////////////////////WIN/////////////////////////////////////////////////
	
bool InstanceCheck::check_with_message() const {
	//Alternative method: create a mutex. cons: Will work only with versions creating this mutex
	///*HANDLE*/ m_mutex = CreateMutex(NULL, TRUE, L"PrusaSlicer");
	//if(GetLastError() == ERROR_ALREADY_EXISTS){} destrucktor -> CloseHandle(m_mutex); 
	
	// Call EnumWidnows with own callback. cons: Based on text in the name of the window and class name which is generic.
	if (!EnumWindows(EnumWindowsProc, 0)) {
		printf("Another instance of PrusaSlicer is already running.\n");
		LPWSTR command_line_args = GetCommandLine();
		HWND hwndListener;
		if ((hwndListener = FindWindow(NULL, L"PrusaSlicer_listener_window")) != NULL)
		{
			send_message(hwndListener);
		}
		else
		{
			printf("Listener window not found - teminating without sent info.\n");
		}
		return true;
	}

	// invisible window with single purpose: catch messages from other instances via its callback
	create_listener_window();
	
	return false;
}

void InstanceCheck::create_listener_window() const {
	WNDCLASSEX wndClass = { 0 };
	wndClass.cbSize = sizeof(WNDCLASSEX);
	wndClass.hInstance = reinterpret_cast<HINSTANCE>(GetModuleHandle(0));
	wndClass.lpfnWndProc = reinterpret_cast<WNDPROC>(WndProc);//this is callback
	wndClass.lpszClassName = L"PrusaSlicer_single_instance_listener_class";
	if (!RegisterClassEx(&wndClass))
	{
		DWORD err = GetLastError();
		return;
	}

	HWND hWnd = CreateWindowEx(
		0,//WS_EX_NOACTIVATE,
		L"PrusaSlicer_single_instance_listener_class",
		L"PrusaSlicer_listener_window",
		WS_OVERLAPPEDWINDOW,//WS_DISABLED, // style
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		NULL, NULL,
		GetModuleHandle(NULL),
		NULL);
	if (hWnd == NULL)
	{
		DWORD err = GetLastError();
	}
	else
	{
		//ShowWindow(hWnd, SW_SHOWNORMAL);
		UpdateWindow(hWnd);
	}
}

void InstanceCheck::send_message(const HWND hwnd) const {
	LPWSTR command_line_args = GetCommandLine();
	std::wcout << L"Sending message: " << command_line_args << std::endl;
	//Create a COPYDATASTRUCT to send the information
	//cbData represents the size of the information we want to send.
	//lpData represents the information we want to send.
	//dwData is an ID defined by us(this is a type of ID different than WM_COPYDATA).
	COPYDATASTRUCT data_to_send = { 0 };
	data_to_send.dwData = 1;
	data_to_send.cbData = sizeof(TCHAR) * (wcslen(command_line_args) + 1);
	data_to_send.lpData = command_line_args;

	SendMessage(hwnd, WM_COPYDATA, 0, (LPARAM)&data_to_send);
}

#elif defined(__APPLE__)  ////////////////////////////////////////APPLE//////////////////////////////////////////////////

bool InstanceCheck::check_with_message() const {
	if(!get_lock()){
	    std::cout<<"Process already running!"<< std::endl;  
	    send_message();
	    return true;
	}
	wrapper_mac->register_for_messages();
	return false;
}

int InstanceCheck::get_lock() const
{
 	struct flock fl;
  	int fdlock;
  	fl.l_type = F_WRLCK;
  	fl.l_whence = SEEK_SET;
  	fl.l_start = 0;
  	fl.l_len = 1;

  	if((fdlock = open("/tmp/prusaslicer.lock", O_WRONLY|O_CREAT, 0666)) == -1)
    	return 0;

  	if(fcntl(fdlock, F_SETLK, &fl) == -1)
    	return 0;

  	return 1;
}

void InstanceCheck::send_message() const {
	wrapper_mac->send_message("");
}

#elif defined(__linux__) ////////////////////////////////////////LINUX//////////////////////////////////////////////////
void InstanceCheck::sig_handler(int signo)
{
	if (signo == SIGUSR1){
  		printf("received SIGUSR1\n");
  		InstanceCheck::instance_check().bring_this_instance_forward();
 	}
   	
  //signal(signo, sig_handler); 
}

bool InstanceCheck::check_with_message() const {
	if(!get_lock()){
	    std::cout<<"Process already running!"<< std::endl;
	    std::string pid_string = get_pid_string_by_name("prusa-slicer");
	    if (pid_string != "")
	    {
	    	std::cout<<"pid "<<pid_string<<std::endl;
	    	int pid = atoi(pid_string.c_str());
	    	if(pid > 0)
	    		kill(pid, SIGUSR1);
	    	//std::string command = "fg ";
	    	//command += pid_string;
	   		//system(command.c_str());
	    }
	    
	    return true;
	}

	if (signal(SIGUSR1, InstanceCheck::sig_handler) == SIG_ERR) {printf("\ncan't catch SIGUSR1\n");}
	return false;
}

int InstanceCheck::get_lock() const
{
 	struct flock fl;
  	int fdlock;
  	fl.l_type = F_WRLCK;
  	fl.l_whence = SEEK_SET;
  	fl.l_start = 0;
  	fl.l_len = 1;

  	if((fdlock = open("/tmp/prusaslicer.lock", O_WRONLY|O_CREAT, 0666)) == -1)
    	return 0;

  	if(fcntl(fdlock, F_SETLK, &fl) == -1)
    	return 0;

  	return 1;
}

std::string InstanceCheck::get_pid_string_by_name(const std::string procName) const
{
    int pid = -1;
    std::string pid_string = "";
    // Open the /proc directory
    DIR *dp = opendir("/proc");
    if (dp != NULL)
    {
        // Enumerate all entries in directory until process found
        struct dirent *dirp;
        while (pid < 0 && (dirp = readdir(dp)))
        {
            // Skip non-numeric entries
            int id = atoi(dirp->d_name);
            if (id > 0)
            {
                // Read contents of virtual /proc/{pid}/cmdline file
                std::string cmdPath = std::string("/proc/") + dirp->d_name + "/cmdline";
                std::ifstream cmdFile(cmdPath.c_str());
                std::string cmdLine;
                getline(cmdFile, cmdLine);
                if (!cmdLine.empty())
                {
                    // Keep first cmdline item which contains the program path
                    size_t pos = cmdLine.find('\0');
                    if (pos != std::string::npos)
                        cmdLine = cmdLine.substr(0, pos);
                    // Keep program name only, removing the path
                    pos = cmdLine.rfind('/');
                    if (pos != std::string::npos)
                        cmdLine = cmdLine.substr(pos + 1);
                    // Compare against requested process name
                    if (cmdLine.find(procName) != std::string::npos) {
    					pid = id;
    					pid_string = dirp->d_name;
					}    
                }

            }
        }
    }

    closedir(dp);

    return pid_string;
}

void InstanceCheck::bring_this_instance_forward() const {
	printf("going forward\n");
	//GUI::wxGetApp().GetTopWindow()->Iconize(false); // restore the window if minimized
    GUI::wxGetApp().GetTopWindow()->SetFocus();  // focus on my window
    GUI::wxGetApp().GetTopWindow()->Raise();  // bring window to front
   	GUI::wxGetApp().GetTopWindow()->Show(true); // show the window
}
void InstanceCheck::send_message(const int pid) const {

}

#endif //_WIN32/__APPLE__/__linux__ ////////////////////////////////////////common//////////////////////////////////////////////////


InstanceCheck::InstanceCheck() 
#if __APPLE__
    :wrapper_mac(new InstanceCheckMac())
#endif
{}
InstanceCheck::~InstanceCheck() {
	#if __APPLE__
	delete wrapper_mac;
#endif
}

void InstanceCheck::handle_message(const std::string message) const {

	/*BOOST_LOG_TRIVIAL(info)*/ std::cout << "New message: " << message << std::endl;

	std::vector<boost::filesystem::path> paths;
	auto next_space = message.find(' ');
	size_t last_space = 0;
	int counter = 0;
	while (next_space != std::string::npos)
	{
		const std::string possible_path = message.substr(last_space, next_space - last_space);
		if (counter != 0 && boost::filesystem::exists(possible_path)) {
			paths.push_back(boost::filesystem::path(possible_path));
		}
		last_space = next_space;
		next_space = message.find(' ', last_space + 1);
		counter++;
	}
	//const std::string possible_path = message.substr(last_space + 1);
	if (counter != 0 && boost::filesystem::exists(message.substr(last_space + 1))) {
		paths.push_back(boost::filesystem::path(message.substr(last_space + 1)));
	}
	if(!paths.empty()){
		GUI::wxGetApp().plater()->load_files(paths, true, true);
	}
	
}
} // namespace Slic3r
