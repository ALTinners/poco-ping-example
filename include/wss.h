#ifndef WEBSOCKETS_INTERFACE_H
#define WEBSOCKETS_INTERFACE_H

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <iostream>
#include <string>
#include <atomic>
#include <fstream>

#include "Poco/ErrorHandler.h"
#include "Poco/Net/HTTPServer.h"
#include "Poco/Net/HTTPRequestHandler.h"
#include "Poco/Net/HTTPRequestHandlerFactory.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/Net/HTTPServerResponse.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Net/ServerSocket.h"
#include <Poco/Net/SecureServerSocket.h>
#include "Poco/Net/WebSocket.h"
#include "Poco/Net/NetException.h"
#include "Poco/Util/Option.h"
#include "Poco/Util/OptionSet.h"
#include "Poco/Util/HelpFormatter.h"
#include "Poco/Format.h"
#include "Poco/Exception.h"

using namespace std;

using Poco::Net::SocketAddress;
using Poco::Net::ServerSocket;
using Poco::Net::SecureServerSocket;
using Poco::Net::WebSocket;
using Poco::Net::WebSocketException;
using Poco::Net::HTTPRequestHandler;
using Poco::Net::HTTPRequestHandlerFactory;
using Poco::Net::HTTPServer;
using Poco::Net::HTTPServerRequest;
using Poco::Net::HTTPResponse;
using Poco::Net::HTTPServerResponse;
using Poco::Net::HTTPServerParams;
using Poco::Timestamp;
using Poco::ThreadPool;
using Poco::Util::Option;
using Poco::Util::OptionSet;
using Poco::Util::HelpFormatter;
using Poco::Net::Context;
using Poco::TimeoutException;

class SSLContext
{
    public:
        /**
         * @brief Constructs an SSL cert object with some validation
         * @param ssl_cert_param The SSL cert location param.
         * @param ssl_key_param The SSL key location param.
         */
        SSLContext(const string& ssl_cert_location,
                    const string& ssl_key_location);

        /**
         * @brief Checks the validity of the SSL context
         * @return If the SSL certificate and private key were loaded successfully
         */
        bool is_valid() const noexcept;

        Poco::Net::Context::Ptr get_poco_context();

        string get_cert() const;

        string get_key() const;

        static const string supported_tls_ciphers;

    private:
        Poco::Net::Context::Ptr poco_ctx_;               ///< The SSL/TLS context for Poco
        bool is_valid_;                     ///< Whether the loading was validated or not

        string cert_;
        string key_;

};

class PageRequestHandler: public HTTPRequestHandler
{
    public:
        void handleRequest(HTTPServerRequest& request, HTTPServerResponse& response);
};

class SubscriberRequestHandler : public HTTPRequestHandler
{
    public:
        SubscriberRequestHandler(const long& timeout_threshold);
        virtual ~SubscriberRequestHandler();

        virtual void handleRequest(HTTPServerRequest& poco_req, HTTPServerResponse& poco_resp);

    protected:
        std::shared_ptr<WebSocket> ws_;

        static constexpr uint32_t MAX_FRAME_SIZE = 1024000; // Approx 1 Mb
        const long timeout_threshold_;          ///< The timeout threshold for IO before a socket is considered broken. In microseconds

        std::atomic_bool should_session_close_;         ///< A threadsafe flag which can be set to indicate when the session should close

};

class WssRequestHandlerFactory : public HTTPRequestHandlerFactory
{
  public:
    WssRequestHandlerFactory(const long& timeout_threshold);

    virtual HTTPRequestHandler* createRequestHandler(const HTTPServerRequest &);

    const long timeout_threshold_;
};


class WssInterface
{
  public:
    /**
     * @brief Constructs the object
     *
     */
    WssInterface(
            const uint16_t& port,
            const long& timeout_threshold,
            Context::Ptr ctx);

    /**
     * @brief ~PocoHttpsInterface - Polymorphic destructor
     */
    virtual ~WssInterface();

    /**
     * @brief Starts the interface accepting incoming messages
     * @return True if success
     */
    bool open();

    /**
     * @brief Closes the interface so it will no longer accept incoming messages
     * @return True if success
     */
    bool close();

    /**
     * @brief Checks if the interface is currently accepting incoming messages
     * @return True if open, false if closed, indeterminate_keyword_t if in error
     */
    bool is_open() const;

  private:
    const uint16_t port_;
    const long timeout_threshold_;
    Context::Ptr ctx_;                       ///< The SSL/TLS context we use for WSS protocol
    std::shared_ptr<HTTPServer> server_;
    std::thread runner_;

};


#endif // WEBSOCKETS_INTERFACE_H
