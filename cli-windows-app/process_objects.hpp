#pragma once

#include <cstdint>
#include <string>

// Thank you sogen!

typedef enum _EVENT_TYPE {
  NotificationEvent,
  SynchronizationEvent
} EVENT_TYPE;

struct ReferenceCountObject {

};

struct Event {
	std::u16string name;
  EVENT_TYPE type;
  bool signaled;
};
