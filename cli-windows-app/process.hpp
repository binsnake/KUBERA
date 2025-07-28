#pragma once

#include <context/KUBERA.hpp>
#include <unordered_map>
#include <map>
#include <memory>
#include <string>
#include <mutex>
#include <random>
#include <expected>
#include <cstdint>
#include <string>
#include "wintypes.hpp"
#include "module_manager.hpp"
#include "handle_registry.hpp"


namespace process
{
  struct HandleTypes {
    enum type : uint16_t {
      reserved = 0,
      file,
      device,
      event,
      section,
      symlink,
      directory,
      semaphore,
      port,
      thread,
      registry,
      mutant,
      token,
      window,
    };
  };

  using handle = windows::HANDLE;
	using handle_value = windows::handle_value;

  inline bool operator==( const handle& h1, const handle& h2 ) {
    return h1.bits == h2.bits;
  }

  inline bool operator==( const handle& h1, const uint64_t& h2 ) {
    return h1.bits == h2;
  }

  inline handle_value get_handle_value ( const uint64_t h ) {
    handle hh {};
    hh.bits = h;
    return hh.value;
  }

  constexpr handle make_handle ( const uint32_t id, const HandleTypes::type type, const bool is_pseudo ) {
    handle_value value {};
    value.padding = 0;
    value.id = id;
    value.type = type;
    value.is_system = false;
    value.is_pseudo = is_pseudo;
    return { value };
  }

  constexpr handle make_handle ( const uint64_t value ) {
    handle h {};
    h.bits = value;
    return h;
  }

  constexpr handle make_pseudo_handle ( const uint32_t id, const HandleTypes::type type ) {
    return make_handle ( id, type, true );
  }

  constexpr auto WER_PORT_READY = make_pseudo_handle ( 0x1, HandleTypes::event );

  enum class HandleStatusCode {
    success,
    not_found,
    invalid_handle
  };

  class ReferencedObject {
  public:
    virtual ~ReferencedObject ( ) = default;
    uint32_t ref_count { 1 };

    static bool deleter ( ReferencedObject& e ) {
      return --e.ref_count == 0;
    }
  };

  // Base class for type erasure in global registry
  class HandleManagerBase {
  public:
    virtual ~HandleManagerBase ( ) = default;
    virtual bool erase ( handle h ) = 0;
    virtual std::optional<handle> duplicate ( handle h ) = 0;
    virtual void* get_raw_object ( handle h ) const = 0;
  };

  class HandleRegistry {
  private:
    struct registry_entry {
      std::unique_ptr<ReferencedObject> object;
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

    bool try_register_handle ( handle h, HandleManagerBase* manager ) { // Changed to HandleManagerBase*
      std::lock_guard<std::mutex> lock ( mutex );
      return handle_map.emplace ( h.bits, registry_entry { nullptr, manager } ).second;
    }

    void register_object ( handle h, ReferencedObject* object ) {
      std::lock_guard<std::mutex> lock ( mutex );
      auto it = handle_map.find ( h.bits );
      if ( it != handle_map.end ( ) ) {
        it->second.object.reset ( object );
      }
    }

    void unregister_handle ( handle h ) {
      std::lock_guard<std::mutex> lock ( mutex );
      handle_map.erase ( h.bits );
    }

    std::pair<ReferencedObject*, HandleManagerBase*> lookup ( handle h ) {
      std::lock_guard<std::mutex> lock ( mutex );
      auto it = handle_map.find ( h.bits );
      if ( it == handle_map.end ( ) ) {
        return { nullptr, nullptr };
      }
      return { it->second.object.get ( ), it->second.manager };
    }
  };

  template <HandleTypes::type Type, typename T, typename NameType = std::string, uint32_t IndexShift = 0>
    requires( std::is_base_of_v<ReferencedObject, T> )
  class HandleManager : public HandleManagerBase {
  private:
    using value_map = std::map<uint32_t, std::unique_ptr<T>>;
    value_map store;
  public:
    mutable std::mutex mutex;

  private:
    std::expected<uint32_t, HandleStatusCode> find_free_index ( ) {
      static std::mt19937 rng { std::random_device{}( ) };
      static std::uniform_int_distribution<uint32_t> dist ( 1, UINT32_MAX );
      uint32_t index;
      for ( int attempts = 100; attempts > 0; --attempts ) {
        index = dist ( rng );
        handle h = make_handle ( index << IndexShift, Type, false );
        if ( !store.contains ( index ) && HandleRegistry::get_instance ( ).try_register_handle ( h, this ) ) {
          return index;
        }
      }
      return std::unexpected ( HandleStatusCode::invalid_handle );
    }

  public:
    template <typename... Args>
    std::expected<handle, HandleStatusCode> create_object ( NameType name, Args&&... args ) {
      static_assert( std::is_constructible_v<T, NameType, Args...>,
                    "Type T must be constructible with NameType and provided arguments" );
      std::lock_guard<std::mutex> lock ( mutex );
      auto index_result = find_free_index ( );
      if ( !index_result ) {
        return std::unexpected ( index_result.error ( ) );
      }
      uint32_t index = *index_result;
      handle h = make_handle ( index << IndexShift, Type, false );
      auto it = store.emplace ( index, std::make_unique<T> ( std::move ( name ), std::forward<Args> ( args )... ) ).first;
      HandleRegistry::get_instance ( ).register_object ( h, it->second.get ( ) );
      return h;
    }

    std::expected<handle, HandleStatusCode> open_object ( const NameType& name ) {
      std::lock_guard<std::mutex> lock ( mutex );
      for ( const auto& [index, obj] : store ) {
        if ( obj && obj->name == name ) {
          ++obj->ref_count;
          return make_handle ( index << IndexShift, Type, false );
        }
      }
      return std::unexpected ( HandleStatusCode::not_found );
    }

    bool erase ( handle h ) override {
      std::lock_guard<std::mutex> lock ( mutex );
      if ( h.value.type != Type || h.value.is_pseudo ) {
        return false;
      }
      uint32_t index = static_cast< uint32_t >( h.value.id ) >> IndexShift;
      auto it = store.find ( index );
      if ( it == store.end ( ) ) {
        return false;
      }
      if ( !T::deleter ( *it->second ) ) {
        return true;
      }
      HandleRegistry::get_instance ( ).unregister_handle ( h );
      store.erase ( it );
      return true;
    }

    std::optional<handle> duplicate ( handle h ) override {
      std::lock_guard<std::mutex> lock ( mutex );
      if ( h.value.type != Type || h.value.is_pseudo ) {
        return std::nullopt;
      }
      uint32_t index = static_cast< uint32_t >( h.value.id ) >> IndexShift;
      auto it = store.find ( index );
      if ( it == store.end ( ) ) {
        return std::nullopt;
      }
      ++it->second->ref_count;
      return h;
    }

    const T* get ( handle h ) const {
      std::lock_guard<std::mutex> lock ( mutex );
      if ( h.value.type != Type || h.value.is_pseudo ) {
        return nullptr;
      }
      uint32_t index = static_cast< uint32_t >( h.value.id ) >> IndexShift;
      auto it = store.find ( index );
      if ( it == store.end ( ) ) {
        return nullptr;
      }
      return it->second.get ( );
    }

    void* get_raw_object ( handle h ) const override {
      return const_cast< void* >( static_cast< const void* >( get ( h ) ) );
    }

    int get_ref_count ( handle h ) const {
      std::lock_guard<std::mutex> lock ( mutex );
      if ( h.value.type != Type || h.value.is_pseudo ) {
        return 0;
      }
      uint32_t index = static_cast< uint32_t >( h.value.id ) >> IndexShift;
      auto it = store.find ( index );
      if ( it == store.end ( ) ) {
        return 0;
      }
      return it->second->ref_count;
    }

    using iterator = typename value_map::iterator;
    using const_iterator = typename value_map::const_iterator;

    iterator begin ( ) {
      return store.begin ( );
    }

    iterator end ( ) {
      return store.end ( );
    }

    const_iterator begin ( ) const {
      return store.begin ( );
    }

    const_iterator end ( ) const {
      return store.end ( );
    }
  };

  struct WinEvent : public ReferencedObject {
    std::u16string name;
    windows::EVENT_TYPE type;
    bool signaled;

    WinEvent ( std::u16string n, windows::EVENT_TYPE t, bool sig = false )
      : name ( std::move ( n ) ), type ( t ), signaled ( sig ) { }
  };

	namespace helpers
	{
	#pragma warning(push)
	#pragma warning(disable: 4244)  // Disable deprecation warnings
		inline std::string u16_to_string ( const std::u16string& u16 ) {
			return std::string ( u16.begin ( ), u16.end ( ) );
		}
	#pragma warning(pop)
	};

	inline kubera::KUBERA ctx { };
	inline ModuleManager mm { ctx.get_virtual_memory ( ) };
	inline HandleManager<HandleTypes::event, WinEvent, std::u16string> event_mgr;

  constexpr auto CURRENT_PROCESS_HANDLE = ~0ULL;
};