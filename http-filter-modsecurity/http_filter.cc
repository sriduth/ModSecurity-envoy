#include <cstdlib>

#include "common/common/logger.h"
#include "envoy/registry/registry.h"

#include <ctime>
#include <chrono>
#include <string>

#include "http_filter.h"
#include "common/common/fmt.h"

#include "envoy/access_log/access_log.h"
#include "envoy/server/filter_config.h"
#include <iostream>

#include "modsecurity/rule_message.h"


using namespace std;

namespace Envoy {
namespace Http {


// NOTE: set this to nullptr in the lifecycle action else the destructior
// call when runtime shuts down will end up in a segfault / core dump
static AccessLog::AccessLogFileSharedPtr log_file = nullptr;

static void writeLog(const std::string& message, const std::string level = "info") {
  static const std::string log_format = "[{}] {} {} \n";

  std::time_t timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  
  std::string log_line = fmt::format(log_format, std::ctime(&timestamp), level, message);

  log_file->write(log_line);
}
    
static void logCb(void *data, const void *ruleMessagev) {
  if (ruleMessagev == NULL) {
    return;
  }
  
  const modsecurity::RuleMessage *ruleMessage = reinterpret_cast<const modsecurity::RuleMessage *>(ruleMessagev);

  const std::string str_rule_id = std::to_string(ruleMessage->m_ruleId);
  const std::string str_m_phase = std::to_string(ruleMessage->m_phase);
  
  writeLog(fmt::format("id: {} phase: {}",
		       str_rule_id,
		       str_m_phase));
		      
  const std::string str_rule_message = modsecurity::RuleMessage::log(ruleMessage);

  if (ruleMessage->m_isDisruptive) {
    writeLog(fmt::format("ruleMessage: disruptive {}", str_rule_message), "warn");
  } else {
    writeLog(fmt::format("ruleMessage: {}", str_rule_message));
  }
}

HttpModSecurityFilterConfig::HttpModSecurityFilterConfig(const modsecurity::Decoder& proto_config,
							 AccessLog::AccessLogFileSharedPtr access_log_file)
{  
  if(!log_file) {
    log_file_ = access_log_file; 
    log_file = this->log_file_;
  }
   
  if(!modsec) {
    writeLog("ModSecurity initializing.");
    modsec = std::make_shared<modsecurity::ModSecurity>();
    modsec->setConnectorInformation("ModSecurity-test v0.0.1-alpha (ModSecurity test)");
  }
  
  
  if(!modsec_rules) {
    std::string rules_file = proto_config.rules();
    modsec_rules = std::make_shared<modsecurity::Rules>();
    int rules_loaded = modsec_rules->loadFromUri(rules_file.c_str());
    
    if(rules_loaded < 0) {
      std::string log = "Failed to load rules_files: " + rules_file;
      writeLog(log, "error");
    }
  }
}

void HttpModSecurityFilterConfig::teardown() {
  log_file = nullptr;
}
  
HttpModSecurityFilter::HttpModSecurityFilter(HttpModSecurityFilterConfigSharedPtr config)
    : config_(config) {
  std::cout << "Create filter" << std::endl;
  this->config_.get()->modsec->setServerLogCb(logCb,
					      modsecurity::RuleMessageLogProperty
					      | modsecurity::IncludeFullHighlightLogProperty);

  modsecTransaction = new modsecurity::Transaction(this->config_.get()->modsec.get(),
						   this->config_.get()->modsec_rules.get(),
						   NULL);

}

HttpModSecurityFilter::~HttpModSecurityFilter() {
  delete this->modsecTransaction;
  this->modsecTransaction = NULL;
}

HttpModSecurityFilterConfig::~HttpModSecurityFilterConfig() {}

void HttpModSecurityFilter::onDestroy() {
  this->modsecTransaction->processLogging();
}

FilterHeadersStatus HttpModSecurityFilter::decodeHeaders(HeaderMap& headers, bool) {
  const char * uri = headers.get(LowerCaseString(":path"))->value().c_str();
  const char * method = headers.get(LowerCaseString(":method"))->value().c_str();
  this->modsecTransaction->processURI(uri, method, "1.1");
  headers.iterate(
         [](const HeaderEntry& header, void* context) -> HeaderMap::Iterate {
            static_cast<HttpModSecurityFilter*>(context)->modsecTransaction->addRequestHeader(
                   header.key().c_str(),
                   header.value().c_str()
          );
          return HeaderMap::Iterate::Continue;
          },
          this);
  this->modsecTransaction->processRequestHeaders();
  return FilterHeadersStatus::Continue;
}

FilterDataStatus HttpModSecurityFilter::decodeData(Buffer::Instance& data, bool) {
  const size_t length = data.length();
  unsigned char * buffer = new unsigned char[length]();

  // TODO: avoid duplicate copy
  data.copyOut(0, length, buffer);
  this->modsecTransaction->appendRequestBody(buffer, length);
  this->modsecTransaction->processRequestBody();
  delete buffer;
  return FilterDataStatus::Continue;
}

FilterTrailersStatus HttpModSecurityFilter::decodeTrailers(HeaderMap&) {
  return FilterTrailersStatus::Continue;
}

void HttpModSecurityFilter::setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}


FilterHeadersStatus HttpModSecurityFilter::encodeHeaders(HeaderMap& headers, bool) {
  int code = atoi(headers.get(LowerCaseString(":status"))->value().c_str());
    headers.iterate(
           [](const HeaderEntry& header, void* context) -> HeaderMap::Iterate {
               static_cast<HttpModSecurityFilter*>(context)->modsecTransaction->addResponseHeader(
                       header.key().c_str(),
                      header.value().c_str()
              );
              return HeaderMap::Iterate::Continue;
         },
          this);
  this->modsecTransaction->processResponseHeaders(code, "1.1");
  return FilterHeadersStatus::Continue;
}

FilterHeadersStatus HttpModSecurityFilter::encode100ContinueHeaders(HeaderMap& headers) {
    return FilterHeadersStatus::Continue;
}

  FilterMetadataStatus HttpModSecurityFilter::encodeMetadata(MetadataMap& map) {
    return FilterMetadataStatus::Continue;
  }
FilterDataStatus HttpModSecurityFilter::encodeData(Buffer::Instance& data, bool) {
    const size_t length = data.length();
    unsigned char * buffer = new unsigned char[length]();

    // TODO: avoid duplicate copy
    data.copyOut(0, length, buffer);
    this->modsecTransaction->appendResponseBody(buffer, length);
    this->modsecTransaction->processResponseBody();
    delete buffer;
    return FilterDataStatus::Continue;
}

FilterTrailersStatus HttpModSecurityFilter::encodeTrailers(HeaderMap&) {
    return FilterTrailersStatus::Continue;
}

void HttpModSecurityFilter::setEncoderFilterCallbacks(StreamEncoderFilterCallbacks& callbacks) {
    encoder_callbacks_ = &callbacks;
}

} // namespace Http
} // namespace Envoy
