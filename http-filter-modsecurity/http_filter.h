#pragma once



#include <string>

#include "envoy/server/filter_config.h"
#include "envoy/access_log/access_log.h"

#include "http-filter-modsecurity/http_filter.pb.h"

#include "modsecurity/modsecurity.h"
#include "modsecurity/rules.h"

namespace Envoy {
namespace Http {

class HttpModSecurityFilterConfig {
public:
  HttpModSecurityFilterConfig(const modsecurity::Decoder& proto_config,
			      AccessLog::AccessLogFileSharedPtr log_file);

  ~HttpModSecurityFilterConfig();

  // Implement this method such that it can be called
  // in the server lifecycle's shutdown callback to clear
  // the static reference to log_file in the implementation
  // of this header
  void teardown();
  
  std::shared_ptr<modsecurity::ModSecurity> modsec;
  std::shared_ptr<modsecurity::Rules> modsec_rules;
  AccessLog::AccessLogFileSharedPtr log_file_;
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
