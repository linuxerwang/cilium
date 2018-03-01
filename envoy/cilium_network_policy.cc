#include "cilium_network_policy.h"
#include "cilium/npds.pb.validate.h"

#include <string>

#include "common/config/grpc_subscription_impl.h"
#include "common/config/utility.h"
#include "common/protobuf/protobuf.h"
#include "envoy/singleton/instance.h"

namespace Envoy {
namespace Cilium {

NetworkPolicyMap::NetworkPolicyMap(const envoy::api::v2::core::ApiConfigSource& api_config_source,
				   const LocalInfo::LocalInfo& local_info,
				   Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
				   ThreadLocal::SlotAllocator& tls,
				   Stats::Scope &scope)
  : tls_(tls.allocateSlot()) {
  Config::Utility::checkApiConfigSourceSubscriptionBackingCluster(cm.clusters(), api_config_source);
  Config::SubscriptionStats stats = Config::Utility::generateStats(scope);

  tls_->set([](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
    return std::make_shared<ThreadLocalPolicyMap>();
  });

  subscription_ = std::make_unique<Config::GrpcSubscriptionImpl<cilium::NetworkPolicy>>(
                      local_info.node(),
		      Config::Utility::factoryForApiConfigSource(cm.grpcAsyncClientManager(),
								 api_config_source,
								 scope)->create(),
		      dispatcher,
		      *Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
                          "cilium.NetworkPolicyDiscoveryService.StreamNetworkPolicies"),
		      stats);
  subscription_->start({}, *this);
}

void NetworkPolicyMap::onConfigUpdate(const ResourceVector& resources) {
  if (resources.empty()) {
    ENVOY_LOG(debug, "Missing Network Policy for {} in onConfigUpdate() versionInfo: ", subscription_->versionInfo());
    return;
  }
  for (const auto& config: resources) {
    ENVOY_LOG(debug, "Received Network Policy in onConfigUpdate() versionInfo: ", subscription_->versionInfo(), " policy id: ", config.policy());

    MessageUtil::validate(config);

    // First find the old config to figure out if an update is needed.
    const uint64_t new_hash = MessageUtil::hash(config);
    const auto& old_policy = GetPolicy(config.policy());
    if (old_policy && old_policy->hash_ == new_hash &&
	Protobuf::util::MessageDifferencer::Equals(old_policy->policy_proto_, config)) {
      ENVOY_LOG(debug, "New policy is equal to old one, not updating.");
      continue;
    }

    auto new_policy = std::make_shared<PolicyInstance>(new_hash, config);
    tls_->runOnAllThreads([this, new_policy]() -> void {
	ENVOY_LOG(debug, "Cilium inserting new network policy for ", new_policy->policy_proto_.policy());
	tls_->getTyped<ThreadLocalPolicyMap>().policies_[new_policy->policy_proto_.policy()] = new_policy;
      });
  }
}

void NetworkPolicyMap::onConfigUpdateFailed(const EnvoyException*) {
  // We need to allow server startup to continue, even if we have a bad
  // config.
  ENVOY_LOG(warn, "Bad Network Policy Configuration");
}

} // namespace Cilium
} // namespace Envoy
