#import <Cocoa/Cocoa.h>

@interface InstanceCheckMessenger : NSObject

-(instancetype) init;
-(void) send_message:(NSString *)msg;
-(void) add_observer;
-(void) message_update:(NSNotification *)note;
@end
