#include <string>

#include "http_filter.h"

#include "extensions/filters/network/mongo_proxy/proxy.h"

#include "common/config/datasource.h"
#include "envoy/registry/registry.h"
#include "absl/types/optional.h"

#include "http-filter-modsecurity/http_filter.pb.h"
#include "http-filter-modsecurity/http_filter.pb.validate.h"

namespace Envoy {
namespace Server {
namespace Configuration {
    
class HttpModSecurityFilterConfig : public NamedHttpFilterConfigFactory {
public:
  Http::FilterFactoryCb createFilterFactory(const Json::Object& json_config, const std::string&,
                                            FactoryContext& context) override {

    Http::EZModSecurityFilterConfig ezConfig;
    
    auto data_source = json_config.getObject("rules");
    
    if(data_source->hasObject("filename")) {
      ezConfig.setPath(data_source->getString("filename"));
    }

    if(data_source->hasObject("inline_string")) {
      ezConfig.setConfigText(data_source->getString("inline_string"));
    }

    ezConfig.setModsecLogPath(json_config.getString("log_path"));
    
    return createFilter(ezConfig, context);
  }
  
  Http::FilterFactoryCb createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                                                     const std::string&,
                                                     FactoryContext& context) override {
    auto protoC = Envoy::MessageUtil::downcastAndValidate<const modsecurity::Decoder&>(proto_config);

    Http::EZModSecurityFilterConfig ezConfig;
    
    ezConfig.setModsecLogPath(protoC.log_path());
    
    auto data_source = protoC.rules();

    if(data_source.specifier_case() == envoy::api::v2::core::DataSource::kFilename) {
      ezConfig.setPath(data_source.filename());
    } else if(data_source.specifier_case() == envoy::api::v2::core::DataSource::kInlineString) {
      ezConfig.setConfigText(data_source.inline_string());
    } else {
      throw EnvoyException("modsecurity filter does not support inline bytes for configuration");
    }
    
    return createFilter(ezConfig, context);
  }

  /**
   *  Return the Protobuf Message that represents your config incase you have config proto
   */
  ProtobufTypes::MessagePtr createEmptyConfigProto() override {

    return ProtobufTypes::MessagePtr{new modsecurity::Decoder()};
  }

  std::string name() override { return "modsecurity"; }

private:
  Http::FilterFactoryCb createFilter(const Http::EZModSecurityFilterConfig& ez_config,
				     FactoryContext& ctx)
  {
    AccessLog::AccessLogFileSharedPtr log_file =
      ctx.accessLogManager().createAccessLog(ez_config.modsec_log_path);
    
    Http::HttpModSecurityFilterConfigSharedPtr config =
      std::make_shared<Http::HttpModSecurityFilterConfig>(ez_config, log_file);

    // register a lifecycle callback so that when the server is terminating,
    // the static reference to the `log_file` created above can be cleaned up.
    // else a pure virtual distructor is called, resulting in a segfault and coredump.
    ctx
      .lifecycleNotifier()
      .registerCallback(ServerLifecycleNotifier::Stage::ShutdownExit, [config]() -> void {
	  config->teardown();
	});
    
    return [config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
      auto filter = new Http::HttpModSecurityFilter(config);
      callbacks.addStreamFilter(Http::StreamFilterSharedPtr{filter});
    };
  }
};

/**
 * Static registration for this sample filter. @see RegisterFactory.
 */
//REGISTER_FACTORY()
static Registry::RegisterFactory<HttpModSecurityFilterConfig, NamedHttpFilterConfigFactory>register_;

} // namespace Configuration
} // namespace Server
} // namespace Envoy
