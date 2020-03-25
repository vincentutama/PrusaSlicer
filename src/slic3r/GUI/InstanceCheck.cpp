#include "GUI_App.hpp"
#include "InstanceCheck.hpp"

//#include "Plater.hpp"

#include <boost/filesystem.hpp>
#include "boost/nowide/convert.hpp"
#include <boost/log/trivial.hpp>
#include <iostream>

#include <fcntl.h>
#include <errno.h>

#if __linux__
#include <dbus/dbus.h> /* Pull in all of D-Bus headers. */
#endif //__linux__

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
void InstanceCheck::bring_this_instance_forward() const 
{
	printf("going forward\n");
	//GUI::wxGetApp().GetTopWindow()->Iconize(false); // restore the window if minimized
    GUI::wxGetApp().GetTopWindow()->SetFocus();  // focus on my window
    GUI::wxGetApp().GetTopWindow()->Raise();  // bring window to front
   	GUI::wxGetApp().GetTopWindow()->Show(true); // show the window
}
static bool dbus_check_error(const char* msg, const DBusError* error) 
{

  	assert(msg != NULL);
  	assert(error != NULL);

  	if (dbus_error_is_set(error)) {
    	fprintf(stderr, msg);
    	fprintf(stderr, "DBusError.name: %s\n", error->name);
    	fprintf(stderr, "DBusError.message: %s\n", error->message);
    	/* If the program wouldn't exit because of the error, freeing the
	       DBusError needs to be done (with dbus_error_free(error)).
	       NOTE:
	         dbus_error_free(error) would only free the error if it was
	         set, so it is safe to use even when you're unsure. */
	    //exit(EXIT_FAILURE);
	    return true;
	}
	return false;
}
void InstanceCheck::send_message(const int pid) const 
{
	
	#define SYSNOTE_NAME  "org.freedesktop.Notifications"
 	#define SYSNOTE_OPATH "/org/freedesktop/Notifications"
 	#define SYSNOTE_IFACE "org.freedesktop.Notifications"
 	#define SYSNOTE_NOTE  "SystemNoteDialog"

  	/* Structure representing the connection to a bus. */
  	DBusConnection* bus = NULL;
  	/* The method call message. */
  	DBusMessage* 	msg = NULL;
 	/* D-Bus will report problems and exceptions using the DBusError
     structure. We'll allocate one in stack (so that we don't need to
     free it explicitly. */
  	DBusError 		error;
  	/* Message to display. */
  	const char* 	dispMsg = "Hello World!";
  	/* Text to use for the acknowledgement button. "" means default. */
 	const char* 	buttonText = "";
  	/* Type of icon to use in the dialog (1 = OSSO_GN_ERROR). We could
     have just used the symbolic version here as well, but that would
     have required pulling the LibOSSO-header files. And this example
     must work without LibOSSO, so this is why a number is used. */
  	int 			iconType = 1;

  	/* Clean the error state. */
  	dbus_error_init(&error);

  	printf("Connecting to Session D-Bus\n");
  	bus = dbus_bus_get(DBUS_BUS_SESSION, &error);
  	if (dbus_check_error("Failed to open Session bus\n", &error))
  		return;
  	assert(bus != NULL);

  	/* Normally one would just do the RPC call immediately without
     checking for name existence first. However, sometimes it's useful
     to check whether a specific name even exists on a platform on
     which you're planning to use D-Bus.

     In our case it acts as a reminder to run this program using the
     run-standalone.sh script when running in the SDK.

     The existence check is not necessary if the recipient is
     startable/activateable by D-Bus. In that case, if the recipient
     is not already running, the D-Bus daemon will start the
     recipient (a process that has been registered for that
     well-known name) and then passes the message to it. This
     automatic starting mechanism will avoid the race condition
     discussed below and also makes sure that only one instance of
     the service is running at any given time. */
  	printf("Checking whether the target name exists (" SYSNOTE_NAME ")\n");
  	if (!dbus_bus_name_has_owner(bus, SYSNOTE_NAME, &error)) {
  		fprintf(stderr, "Name has no owner on the bus!\n");
    	return;
  	}
  	if (dbus_check_error("Failed to check for name ownership\n", &error))
  		return;
  	/* Someone on the Session bus owns the name. So we can proceed in
     relative safety. There is a chance of a race. If the name owner
     decides to drop out from the bus just after we check that it is
     owned, our RPC call (below) will fail anyway. */

  	/* Construct a DBusMessage that represents a method call.
     Parameters will be added later. The internal type of the message
     will be DBUS_MESSAGE_TYPE_METHOD_CALL. */
  	printf("Creating a message object\n");
  	msg = dbus_message_new_method_call(SYSNOTE_NAME, /* destination */
                                       SYSNOTE_OPATH,  /* obj. path */
                                       SYSNOTE_IFACE,  /* interface */
                                       SYSNOTE_NOTE); /* method str */
  	if (msg == NULL) {
    	fprintf(stderr, "Ran out of memory when creating a message\n");
    	return;
  	}

  	/* Set the "no-reply-wanted" flag into the message. This also means
     that we cannot reliably know whether the message was delivered or
     not, but since we don't have reply message handling here, it
     doesn't matter. The "no-reply" is a potential flag for the remote
     end so that they know that they don't need to respond to us.

     If the no-reply flag is set, the D-Bus daemon makes sure that the
     possible reply is discarded and not sent to us. */
  	dbus_message_set_no_reply(msg, TRUE);

  	/* Add the arguments to the message. For the Note dialog, we need
     three arguments:
       arg0: (STRING) "message to display, in UTF-8"
       arg1: (UINT32) type of dialog to display. We will use 1.
                      (libosso.h/OSSO_GN_ERROR).
       arg2: (STRING) "text to use for the ack button". "" means
                      default text (OK in our case).

     When listing the arguments, the type needs to be specified first
     (by using the libdbus constants) and then a pointer to the
     argument content needs to be given.

     NOTE: It is always a pointer to the argument value, not the value
           itself!

     We terminate the list with DBUS_TYPE_INVALID. */
  	printf("Appending arguments to the message\n");
  	if (!dbus_message_append_args(msg,
                                  DBUS_TYPE_STRING, &dispMsg,
                                  DBUS_TYPE_UINT32, &iconType,
                                  DBUS_TYPE_STRING, &buttonText,
                                  DBUS_TYPE_INVALID)) {
    	fprintf(stderr, "Ran out of memory while constructing args\n");
    	return;
  	}

  	printf("Adding message to client's send-queue\n");
  	/* We could also get a serial number (dbus_uint32_t) for the message
     so that we could correlate responses to sent messages later. In
     our case there won't be a response anyway, so we don't care about
     the serial, so we pass a NULL as the last parameter. */
  	if (!dbus_connection_send(bus, msg, NULL)) {
    	fprintf(stderr, "Ran out of memory while queueing message\n");
    	return;
  	}

  	printf("Waiting for send-queue to be sent out\n");
  	dbus_connection_flush(bus);

  	printf("Queue is now empty\n");

  	/* Now we could in theory wait for exceptions on the bus, but since
     this is only a simple D-Bus example, we'll skip that. */

  	printf("Cleaning up\n");

  	/* Free up the allocated message. Most D-Bus objects have internal
     reference count and sharing possibility, so _unref() functions
     are quite common. */
  	dbus_message_unref(msg);
  	msg = NULL;

  	/* Free-up the connection. libdbus attempts to share existing
     connections for the same client, so instead of closing down a
     connection object, it is unreferenced. The D-Bus library will
     keep an internal reference to each shared connection, to
     prevent accidental closing of shared connections before the
     library is finalized. */
  	dbus_connection_unref(bus);
  	bus = NULL;

  	printf("Quitting (success)\n");
   
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
