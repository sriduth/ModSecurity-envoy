#pragma once



#include <string>

#include "envoy/server/filter_config.h"
#include "envoy/access_log/access_log.h"
#include "envoy/stats/scope.h"

#include "http-filter-modsecurity/http_filter.pb.h"

#include "modsecurity/modsecurity.h"
#include "modsecurity/rules.h"

namespace Envoy {
namespace Http {


// wrap the actual configuration of modsecurity inside this
// so we can save on no converting json to proto and vice versa.
class EZModSecurityFilterConfig {
public:
  std::string value;
  std::string type; // indicates the type of configuration (path / config_text);
  std::string modsec_log_path;
  
  EZModSecurityFilterConfig();

  ~EZModSecurityFilterConfig();

  // set either the path or the config text
  void setPath(std::string path);
  void setConfigText(std::string config_text);

  // set the path of the modsecurity log
  void setModsecLogPath(std::string path = "/var/log/envoy/modsec.log");
};
 
class HttpModSecurityFilterConfig {
public:
  HttpModSecurityFilterConfig(const Http::EZModSecurityFilterConfig& ez_config,
			      AccessLog::AccessLogFileSharedPtr log_file,
			      Stats::Scope& scope);

  ~HttpModSecurityFilterConfig();

  // Implement this method such that it can be called
  // in the server lifecycle's shutdown callback to clear
  // the static reference to log_file in the implementation
  // of this header
  void teardown();
  
  std::shared_ptr<modsecurity::ModSecurity> modsec;
  std::shared_ptr<modsecurity::Rules> modsec_rules;
  AccessLog::AccessLogFileSharedPtr log_file_;
  Stats::Scope& scope_;
};

typedef std::shared_ptr<HttpModSecurityFilterConfig> HttpModSecurityFilterConfigSharedPtr;

class HttpModSecurityFilter : public StreamFilter {
public:
  HttpModSecurityFilter(HttpModSecurityFilterConfigSharedPtr);
  ~HttpModSecurityFilter();

  // Http::StreamFilterBase
  void onDestroy() override;
  //  void logCb(void *data, const void *ruleMessagev);
  
  // Http::StreamDecoderFilter
  FilterHeadersStatus decodeHeaders(HeaderMap&, bool) override;
  FilterDataStatus decodeData(Buffer::Instance&, bool) override;
  FilterTrailersStatus decodeTrailers(HeaderMap&) override;
  void setDecoderFilterCallbacks(StreamDecoderFilterCallbacks&) override;

  // Http::StreamEncoderFilter
  FilterMetadataStatus encodeMetadata(MetadataMap& metadata_map) override;
  FilterHeadersStatus encode100ContinueHeaders(HeaderMap& headers) override;
  FilterHeadersStatus encodeHeaders(HeaderMap&, bool) override;
  FilterDataStatus encodeData(Buffer::Instance&, bool) override;
  FilterTrailersStatus encodeTrailers(HeaderMap&) override;
  void setEncoderFilterCallbacks(StreamEncoderFilterCallbacks&) override;
  
private:
  const HttpModSecurityFilterConfigSharedPtr config_;
  StreamDecoderFilterCallbacks* decoder_callbacks_;
  StreamEncoderFilterCallbacks* encoder_callbacks_;
  modsecurity::Transaction * modsecTransaction;
};

} // namespace Http
} // namespace Envoy
