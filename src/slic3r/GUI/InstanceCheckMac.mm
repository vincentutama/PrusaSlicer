#import "InstanceCheck.hpp"
#import "InstanceCheckMac.h"

@implementation InstanceCheckMessenger

-(instancetype) init
{
	self = [super init];
	return self;
}

-(void)send_message:(NSString *)msg
{
	//[[NSDistributedNotificationCenter defaultCenter] postNotificationName:@"OtherPrusaSlicerTerminating" object:nil];
    [[NSDistributedNotificationCenter defaultCenter] postNotificationName:@"OtherPrusaSlicerTerminating" object:nil userInfo:[NSDictionary dictionaryWithObject:msg forKey:@"data"]];
}

-(void)add_observer
{
	[[NSDistributedNotificationCenter defaultCenter] addObserver:self selector:@selector(message_update:) name:@"OtherPrusaSlicerTerminating" object:nil];
}

-(void)message_update:(NSNotification *)note
{
	NSLog(@"got message");
	//NSLog(note);
}

@end

namespace Slic3r {
InstanceCheckMac::InstanceCheckMac(){
	m_mssngr = [[InstanceCheckMessenger alloc] init];
}
InstanceCheckMac::~InstanceCheckMac(){
	if(m_mssngr)
	{
		[m_mssngr release];
	}
}
void InstanceCheckMac::send_message(const std::string msg)
{
	if(m_mssngr)
	{
		[m_mssngr send_message];
	}
}
void InstanceCheckMac::register_for_messages()
{
	if(m_mssngr)
	{
		[m_mssngr add_observer];
	}
}
}//namespace Slicer


