#pragma once

#include "envoy/local_info/local_info.h"
#include "envoy/upstream/cluster_manager.h"
#include "envoy/event/dispatcher.h"

#include "common/common/logger.h"
#include "envoy/config/subscription.h"
#include "envoy/singleton/instance.h"
#include "envoy/thread_local/thread_local.h"

#include "cilium/npds.pb.h"

namespace Envoy {
namespace Cilium {

class NetworkPolicyMap : public Singleton::Instance,
                         Config::SubscriptionCallbacks<cilium::NetworkPolicy>,
                         Logger::Loggable<Logger::Id::config> {
public:
  NetworkPolicyMap(const envoy::api::v2::core::ApiConfigSource& api_config_source,
		   const LocalInfo::LocalInfo& local_info,
		   Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
		   ThreadLocal::SlotAllocator& tls,
		   Stats::Scope &scope);

  class PolicyInstance {
  public:
    PolicyInstance(uint64_t hash, const cilium::NetworkPolicy& proto)
        : hash_(hash), policy_proto_(proto) {}
    uint64_t hash_;
    cilium::NetworkPolicy policy_proto_;
  };

  struct ThreadLocalPolicyMap : public ThreadLocal::ThreadLocalObject {
    std::map<uint32_t, std::shared_ptr<PolicyInstance>> policies_;
  };

  const std::shared_ptr<PolicyInstance>& GetPolicy(uint32_t id) const {
    const ThreadLocalPolicyMap& map = tls_->getTyped<ThreadLocalPolicyMap>();
    auto it = map.policies_.find(id);
    if (it == map.policies_.end()) {
      return null_instance_;
    }
    return it->second;
  }

  // Config::SubscriptionCallbacks
  void onConfigUpdate(const ResourceVector& resources) override;
  void onConfigUpdateFailed(const EnvoyException* e) override;
  std::string resourceName(const ProtobufWkt::Any& resource) override {
    std::string name = fmt::format("{}",
				   MessageUtil::anyConvert<cilium::NetworkPolicy>(resource).policy());
    return name;
  }
    
private:
  ThreadLocal::SlotPtr tls_;
  std::unique_ptr<Envoy::Config::Subscription<cilium::NetworkPolicy>> subscription_;
  const std::shared_ptr<PolicyInstance> null_instance_{nullptr};
};

} // namespace Cilium
} // namespace Envoy
