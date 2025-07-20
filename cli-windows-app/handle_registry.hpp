#pragma once

#include <unordered_map>
#include <mutex>
#include <cstdint>

class HandleManagerBase;

class HandleRegistry {
private:
  struct registry_entry {
    void* object;
    HandleManagerBase* manager;
  };

  std::unordered_map<uint64_t, registry_entry> handle_map;
  std::mutex mutex;

  HandleRegistry ( ) = default;

public:
  static HandleRegistry& get_instance ( ) {
    static HandleRegistry instance;
    return instance;
  }

  bool try_register_handle ( uint64_t handle, HandleManagerBase* manager ) {
    std::lock_guard<std::mutex> lock ( mutex );
    return handle_map.emplace ( handle, registry_entry { nullptr, manager } ).second;
  }

  void register_object ( uint64_t handle, void* object ) {
    std::lock_guard<std::mutex> lock ( mutex );
    auto it = handle_map.find ( handle );
    if ( it != handle_map.end ( ) ) {
      it->second.object = object;
    }
  }

  void unregister_handle ( uint64_t handle ) {
    std::lock_guard<std::mutex> lock ( mutex );
    handle_map.erase ( handle );
  }

  std::pair<void*, HandleManagerBase*> lookup ( uint64_t handle ) {
    std::lock_guard<std::mutex> lock ( mutex );
    auto it = handle_map.find ( handle );
    if ( it == handle_map.end ( ) ) {
      return { nullptr, nullptr };
    }
    return { it->second.object, it->second.manager };
  }
};