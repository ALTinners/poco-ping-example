
#include "include/wss.h"

const string SSLContext::supported_tls_ciphers =
        "ECDHE-RSA-AES128-GCM-SHA256\
        :ECDHE-ECDSA-AES128-GCM-SHA256\
        :ECDHE-RSA-AES256-GCM-SHA384\
        :ECDHE-ECDSA-AES256-GCM-SHA384\
        :DHE-RSA-AES128-GCM-SHA256\
        :kEDH+AESGCM\
        :ECDHE-RSA-AES128-SHA256\
        :ECDHE-ECDSA-AES128-SHA256\
        :ECDHE-RSA-AES128-SHA\
        :ECDHE-ECDSA-AES128-SHA\
        :ECDHE-RSA-AES256-SHA384\
        :ECDHE-ECDSA-AES256-SHA384\
        :ECDHE-RSA-AES256-SHA\
        :ECDHE-ECDSA-AES256-SHA\
        :DHE-RSA-AES128-SHA256\
        :DHE-RSA-AES128-SHA\
        :DHE-RSA-AES256-SHA256\
        :DHE-RSA-AES256-SHA\
        :!aNULL\
        :!eNULL\
        :!EXPORT\
        :!DSS\
        :!DES\
        :!RC4\
        :!3DES\
        :!MD5\
        :!PSK";

SSLContext::SSLContext(const string& ssl_cert_location, const string& ssl_key_location)
    : is_valid_(false)
{
    if (ssl_cert_location.size() > 0 && ssl_key_location.size() > 0)
    {
        is_valid_ = true;

        string cert, key;

        ifstream filestream;
        filestream.open(ssl_cert_location.c_str(), fstream::in);
        if (filestream.is_open())
        {
            try
            {
                cert = static_cast<stringstream const&>(stringstream() << filestream.rdbuf()).str();
            }
            catch (std::exception e)
            {
                cerr << "Reading SSL cert error - " << e.what() << endl;
                is_valid_ &= false;
            }
            filestream.close();
        }
        else
        {
            cerr << "Reading SSL cert error - could not open cert at " << ssl_cert_location << endl;
            is_valid_ &= false;
        }

        filestream.open(ssl_key_location.c_str(), fstream::in);
        if (filestream.is_open())
        {
            try
            {
                key = static_cast<stringstream const&>(stringstream() << filestream.rdbuf()).str();
            }
            catch (std::exception e)
            {
                cerr << "Reading SSL key error - " << e.what() << endl;
                is_valid_ &= false;
            }
            filestream.close();
        }
        else
        {
            cerr << "Reading SSL key error - could not open cert at " << ssl_key_location << endl;
            is_valid_ &= false;
        }

        if (is_valid_)
        {
            cout << "Succesfully loaded SSL cert and key" << endl;

            try
            {
                using namespace Poco::Net;
                poco_ctx_ = new Context(
                                Context::TLSV1_2_SERVER_USE,
                                ssl_key_location,
                                ssl_cert_location,
                                "",
                                Context::VERIFY_RELAXED,
                                9,
                                true,
                                SSLContext::supported_tls_ciphers
                            );

                //To enable ssl session caching we need to generate a random string on initialisation
                // I'm not super sure on what requirements are needed for this string to work safely
                // although from what I can see it just needs to be unique for each startup
                string session_id = "";
                for (int i = 0; i < 80; ++i)
                {
                    session_id += static_cast<unsigned char>(rand() % std::numeric_limits<unsigned char>::max());
                }

                poco_ctx_->enableSessionCache(true, session_id);
            }
            catch (std::exception e)
            {
                cerr << "Exception in constructing POCO SSL context - " << e.what() << endl;
                is_valid_ &= false;
            }

            cert_ = cert;
            key_ = key;
        }
    }
    else
    {
        cerr << "SSL cert and key paths could not be loaded" << endl;
        is_valid_ = false;
    }
}


bool SSLContext::is_valid() const noexcept
{
    return is_valid_;
}

Poco::Net::Context::Ptr SSLContext::get_poco_context()
{
    if (!is_valid_ && poco_ctx_)
    {
        throw std::invalid_argument("The ssl parameters provided did not produce a usable SSL context");
    }
    return poco_ctx_;
}

string SSLContext::get_cert() const
{
    return cert_;
}

string SSLContext::get_key() const
{
    return key_;
}

void PageRequestHandler::handleRequest(HTTPServerRequest& , HTTPServerResponse& response)
{
    response.setStatus(HTTPResponse::HTTP_BAD_REQUEST);
    response.setChunkedTransferEncoding(true);
    std::ostream& ostr = response.send();
    ostr.flush();
}

SubscriberRequestHandler::SubscriberRequestHandler(const long& timeout_threshold)
    : HTTPRequestHandler()
    , timeout_threshold_(timeout_threshold)
    , should_session_close_(false)
{
}

SubscriberRequestHandler::~SubscriberRequestHandler()
{
}

void SubscriberRequestHandler::handleRequest(HTTPServerRequest& request, HTTPServerResponse& response)
{
    try
    {
        cerr << "Got2" << endl;
        ws_ = std::make_shared<WebSocket>(request, response);
        ws_->setSendTimeout(Poco::Timespan(timeout_threshold_, 0));     //s, ns
        ws_->setReceiveTimeout(Poco::Timespan(1.0, 0));
        ws_->setSendBufferSize(MAX_FRAME_SIZE);
        ws_->setBlocking(true);
        char buffer[MAX_FRAME_SIZE];
        int flags = 0;
        int bytes_recv;
        bool timeout_did_occur = false;

        std::chrono::system_clock::time_point last_contact = std::chrono::system_clock::now();

        //Begin looping for reads
        do
        {
            try
            {
                timeout_did_occur = false;
                bytes_recv = ws_->receiveFrame(buffer, sizeof(buffer), flags);

                //If a ping, return a pong
                if ((flags & WebSocket::FRAME_OP_BITMASK) == WebSocket::FRAME_OP_PING)
                {
                    last_contact = std::chrono::system_clock::now();
                    ws_->sendFrame(buffer, bytes_recv, WebSocket::FRAME_OP_PONG);
                    if (bytes_recv == 0)
                    {
                        bytes_recv = 1; //Add some "data" to satisfy our exit condition loop
                    }
                }
                //If a pong, note the recv time
                else if ((flags & WebSocket::FRAME_OP_BITMASK) == WebSocket::FRAME_OP_PONG)
                {
                    last_contact = std::chrono::system_clock::now();
                }
                else if (bytes_recv > 0 && (flags & WebSocket::FRAME_OP_BITMASK) != WebSocket::FRAME_OP_CLOSE)
                {
                    last_contact = std::chrono::system_clock::now();

                    string payload;

                    if ((flags & WebSocket::FRAME_OP_BITMASK) == WebSocket::FRAME_OP_BINARY)
                    {
                        //Do binary things
                    }
                    else
                    {
                        //Else text
                    }
                }
            }
            catch (TimeoutException& exc)
            {
                //This is an accepable condition - it seems we have to repeatedly poll the WSS for socket data
                //A return value of 0 from recieveFrame indicates a broken connection so we also need to check for timeouts as well as broken clients
                //However this timeout alone is not enough for us to indicate that a connection is broken
            }


            auto now = std::chrono::system_clock::now();
            auto time_since_last_contact = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_contact).count();
            if (time_since_last_contact > (timeout_threshold_ * 1000))
            {
                timeout_did_occur = true;
            }

            //Keep open while we have an unbroken socket, timeouts are not occurring or are ignored,
            //  no signal to close is raised, and the client has not specuified a close frame
            if ( (bytes_recv != 0 && !timeout_did_occur)
                    && !should_session_close_
                    && (flags & WebSocket::FRAME_OP_BITMASK) != WebSocket::FRAME_OP_CLOSE)
            {
                // send a server side ping - webpages in js need this
                char ping[] = {};
                ws_->sendFrame(ping, 0, WebSocket::FRAME_OP_PING);

                string donkey = "donkey";
                ws_->sendFrame(donkey.c_str(), sizeof(donkey.c_str()), WebSocket::FRAME_OP_PING);

                // Continue in this case as the timeout is not reached
                continue;
            }

            //Otherwise, signal that the WSS is closing by raising the should_session_close_ flag.
            should_session_close_ = true;
            //Break at the end.
            break;
        }
        while (1);

       std::cout << "Closed at end of loop" << std::endl;
    }
    catch (WebSocketException& exc)
    {
        std::cout << "Hit exception in recv: " << exc.what() << endl;
        switch (exc.code())
        {
        case WebSocket::WS_ERR_HANDSHAKE_UNSUPPORTED_VERSION:
            response.set("Sec-WebSocket-Version", WebSocket::WEBSOCKET_VERSION);
            // fallthrough
        case WebSocket::WS_ERR_NO_HANDSHAKE:
        case WebSocket::WS_ERR_HANDSHAKE_NO_VERSION:
        case WebSocket::WS_ERR_HANDSHAKE_NO_KEY:
            response.setStatusAndReason(HTTPResponse::HTTP_BAD_REQUEST);
            response.setContentLength(0);
            response.send();
            break;
        }
    }
    //Catch all non WSS specific POCO exceptions
    catch (Poco::Exception& exc)
    {
        stringstream ss{};
        ss << string(exc.className()) << " : " << string(exc.message()) << " on thread " << std::this_thread::get_id();
        std::string type = ss.str();
        cerr << "Hit exception in WSS handling - " << type << endl;
    }
    //Catch all std exceptions from the POCO level
    catch (std::exception& exc)
    {
        stringstream ss{};
        ss << exc.what() << " on thread " << std::this_thread::get_id();
        std::string type = ss.str();
        cerr << "Hit exception in WSS handling - " << type << endl;
    }
}

WssRequestHandlerFactory::WssRequestHandlerFactory(const long& timeout_threshold)
    : HTTPRequestHandlerFactory()
    , timeout_threshold_(timeout_threshold)
{
}

HTTPRequestHandler* WssRequestHandlerFactory::createRequestHandler(const HTTPServerRequest& request)
{
    cerr << "Got1" << endl;
    if(request.find("Upgrade") != request.end() && Poco::icompare(request["Upgrade"], "websocket") == 0 )
    {
        SubscriberRequestHandler* session = new SubscriberRequestHandler(timeout_threshold_);
        return session;
    }
    else
    {
        return new PageRequestHandler;
    }
}

WssInterface::WssInterface(
        const uint16_t& port,
        const long& timeout_threshold,
        Context::Ptr ctx)
    : port_(port)
    , timeout_threshold_(timeout_threshold)
    , ctx_(ctx)
{
}

WssInterface::~WssInterface()
{
}

bool WssInterface::open()
{
    if (is_open())
    {
        return true;
    }
    runner_ = std::thread([&]() {
        try
        {
            cerr << "Got" << endl;
            string address_string = "0.0.0.0";
            string port_string = to_string(port_);
            SecureServerSocket svs(SocketAddress(address_string + ":" + port_string), 64, Poco::AutoPtr<Context>(ctx_));

            HTTPServerParams* params = new HTTPServerParams;
            params->setTimeout(Poco::Timespan(3, 0));

            server_ = std::make_shared<HTTPServer>(new WssRequestHandlerFactory(timeout_threshold_), svs, params);
            server_->start();
        }
        catch (Poco::Exception e)
        {
            std::cerr << e.message() << std::endl;
            throw e;
        }
        catch (std::exception e)
        {
            std::cerr << e.what() << std::endl;
            throw e;
        }
    });
    return true;
}

bool WssInterface::close()
{
    if (is_open())
    {
        server_->stopAll(true);
        while(server_->currentConnections() > 0)
        {
            std::cerr << "Shutting down WSS Server - current connections is " << server_->currentConnections() << std::endl;
            usleep(100000);
        }
        runner_.join();
        server_ = std::shared_ptr<HTTPServer>();
        cout << "WSS Server stopped" << endl;
    }
    return true;
}

bool WssInterface::is_open() const
{
    return (server_ != nullptr);
}

int main()
{
    auto ssl_context_ = new SSLContext{"your ssl cert here", "your ssl key here"};

    auto wss_timeout_threshold = 3;
    auto wss_port = 15431;

    auto wss_interface_ = new WssInterface(
                wss_port,
                wss_timeout_threshold,
                ssl_context_->get_poco_context());

    wss_interface_->open();

    while (1) {
        usleep(5000);
    }

    return 0;
}