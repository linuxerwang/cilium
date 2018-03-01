#include "cilium_bpf_metadata.h"
#include "cilium/cilium_bpf_metadata.pb.validate.h"

#include <string>

#include "envoy/network/listen_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"
#include "envoy/singleton/manager.h"

#include "common/common/assert.h"

namespace Envoy {
namespace Server {
namespace Configuration {

// Singleton registration via macro defined in envoy/singleton/manager.h
SINGLETON_MANAGER_REGISTRATION(cilium_network_policy);

/**
 * Config registration for the bpf metadata filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class BpfMetadataConfigFactory : public NamedListenerFilterConfigFactory {
public:
  // NamedListenerFilterConfigFactory
  Configuration::ListenerFilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& proto_config,
			       Configuration::ListenerFactoryContext& context) override {
    auto& bpf_config = MessageUtil::downcastAndValidate<const ::cilium::BpfMetadata&>(proto_config);
    // Get the shared policy provider, or create it if not already created.
    // Note that the API config source is assumed to be the same for all filter instances!
    std::shared_ptr<Cilium::NetworkPolicyMap> npmap =
      context.singletonManager().getTyped<Cilium::NetworkPolicyMap>(
          SINGLETON_MANAGER_REGISTERED_NAME(cilium_network_policy), [&bpf_config, &context] {
            return std::make_shared<Cilium::NetworkPolicyMap>(
	        bpf_config.api_config_source(), context.localInfo(), context.clusterManager(),
		context.dispatcher(), context.threadLocal(), context.scope());
          });
    Filter::BpfMetadata::ConfigSharedPtr config(
        new Filter::BpfMetadata::Config(bpf_config, context.scope(), npmap));
    // Set the socket mark option for the listen socket.
    context.setListenSocketOptions(std::make_shared<Cilium::SocketMarkOption>(config->getMark(config->identity_)));

    return [config](Network::ListenerFilterManager &filter_manager) mutable -> void {
      filter_manager.addAcceptFilter(std::make_unique<Filter::BpfMetadata::Instance>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::BpfMetadata>();
  }

  std::string name() override { return "cilium.bpf_metadata"; }
};

/**
 * Static registration for the bpf metadata filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<BpfMetadataConfigFactory,
                                 NamedListenerFilterConfigFactory>
    registered_;

} // namespace Configuration
} // namespace Server

namespace Filter {
namespace BpfMetadata {

Config::Config(const ::cilium::BpfMetadata &config, Stats::Scope &scope,
	       const std::shared_ptr<Cilium::NetworkPolicyMap> npmap)
    : bpf_root_(config.bpf_root().length() ? config.bpf_root() : "/sys/fs/bpf"),
      stats_{ALL_BPF_METADATA_STATS(POOL_COUNTER(scope))}, is_ingress_(config.is_ingress()),
      identity_(config.identity()), maps_(bpf_root_, *this), npmap_(npmap) {}

bool Instance::getBpfMetadata(Network::ConnectionSocket &socket) {
  return config_->maps_.getBpfMetadata(socket);
}

Network::FilterStatus Instance::onAccept(Network::ListenerFilterCallbacks &cb) {
  Network::ConnectionSocket &socket = cb.socket();
  if (!getBpfMetadata(socket)) {
    ENVOY_LOG(warn,
              "cilium.bpf_metadata ({}): no bpf metadata for the connection.",
              config_->is_ingress_ ? "ingress" : "egress");
  } else {
    ENVOY_LOG(debug,
              "cilium.bpf_metadata ({}): GOT bpf metadata for new connection "
              "(mark: {:x})",
              config_->is_ingress_ ? "ingress" : "egress", socket.options()->hashKey());
  }

  // find policy for the new connection
  // XXX: Integration test passes in a nullptr, need to test for it.
  if (config_->npmap_) {
    const auto& policy = config_->npmap_->GetPolicy(config_->identity_);
    if (!policy) {
      ENVOY_LOG(warn,
		"cilium.bpf_metadata ({}): no network policy was found for the connection.",
		config_->is_ingress_ ? "ingress" : "egress");
    } else {
      ENVOY_LOG(debug,
		"cilium.bpf_metadata ({}): network policy was found for the connection.",
		config_->is_ingress_ ? "ingress" : "egress");
    }
  }
  return Network::FilterStatus::Continue;
}

} // namespace BpfMetadata
} // namespace Filter
} // namespace Envoy
