#ifndef SOCKET_UWS_H
#define SOCKET_UWS_H

#include <openssl/err.h>
#include "Networking.h"
#include <sys/uio.h>
#include <new>

namespace uS {

struct TransferData {
    // Connection state
    uv_os_sock_t fd;
    SSL *ssl;

    // Poll state
    void (*pollCb)(Poll *, int, int);
    int pollEvents;

    // User state
    void *userData;

    // Destination
    NodeData *destination;
    void (*transferCb)(Poll *);
};

// perfectly 64 bytes (4 + 60)
struct WIN32_EXPORT Socket : Poll {
protected:
    struct {
        int poll : 4;
        int shuttingDown : 4;
    } state = {0, false};

    SSL *ssl;
    void *user = nullptr;
    NodeData *nodeData;

    // this is not needed by HttpSocket!
    struct Queue {
        struct Message {
            const char *data;
            size_t length;
            // Per-recipient prefix bytes injected at send time. prefixLength == 0 = legacy
            // single-buffer path; > 0 = scatter-gather. Stored inline so each queued Message
            // owns its own copy.
            uint8_t prefix[8];
            uint8_t prefixLength;
            // When non-null: this Message owns a malloc'd buffer (pop() must `delete[]` it).
            // Used by partial-write flatten path; distinct from `data` because `data` may
            // advance past allocation start during partial drains.
            char *flatOwned;
            Message *nextMessage;
            void (*callback)(void *socket, void *data, bool cancelled, void *reserved);
            void *callbackData, *reserved;
        };

        static_assert(sizeof(Message) <= 96,
                      "Queue::Message size budget exceeded — verify pool bucket sizing");

        // Centralized zero-init for all fields that callers don't immediately overwrite.
        // ALL allocation sites that cast raw memory (pool blocks, new char[]) MUST call this.
        static inline void initMessage(Message *m) {
            std::memset(m->prefix, 0, sizeof(m->prefix));
            m->prefixLength = 0;
            m->flatOwned = nullptr;
            m->nextMessage = nullptr;
            m->callback = nullptr;
            m->callbackData = nullptr;
            m->reserved = nullptr;
        }

        Message *head = nullptr, *tail = nullptr;
        void pop()
        {
            Message *nextMessage;
            if (head->flatOwned) {
                delete [] head->flatOwned;
            }
            if ((nextMessage = head->nextMessage)) {
                delete [] (char *) head;
                head = nextMessage;
            } else {
                delete [] (char *) head;
                head = tail = nullptr;
            }
        }

        bool empty() {return head == nullptr;}
        Message *front() {return head;}

        void push(Message *message)
        {
            message->nextMessage = nullptr;
            if (tail) {
                tail->nextMessage = message;
                tail = message;
            } else {
                head = message;
                tail = message;
            }
        }
    } messageQueue;

    int getPoll() {
        return state.poll;
    }

    int setPoll(int poll) {
        state.poll = poll;
        return poll;
    }

    void setShuttingDown(bool shuttingDown) {
        state.shuttingDown = shuttingDown;
    }

    void transfer(NodeData *nodeData, void (*cb)(Poll *)) {
        // userData is invalid from now on till onTransfer
        setUserData(new TransferData({getFd(), ssl, getCb(), getPoll(), getUserData(), nodeData, cb}));
        stop(this->nodeData->loop);
        close(this->nodeData->loop, [](Poll *p) {
            Socket *s = (Socket *) p;
            TransferData *transferData = (TransferData *) s->getUserData();

            transferData->destination->asyncMutex->lock();
            bool wasEmpty = transferData->destination->transferQueue.empty();
            transferData->destination->transferQueue.push_back(s);
            transferData->destination->asyncMutex->unlock();

            if (wasEmpty) {
                transferData->destination->async->send();
            }
        });
    }

    void changePoll(Socket *socket) {
        if (!threadSafeChange(nodeData->loop, this, socket->getPoll())) {
            if (socket->nodeData->tid != pthread_self()) {
                socket->nodeData->asyncMutex->lock();
                socket->nodeData->changePollQueue.push_back(socket);
                socket->nodeData->asyncMutex->unlock();
                socket->nodeData->async->send();
            } else {
                change(socket->nodeData->loop, socket, socket->getPoll());
            }
        }
    }

    // clears user data!
    template <void onTimeout(Socket *)>
    void startTimeout(int timeoutMs = 15000) {
        Timer *timer = new Timer(nodeData->loop);
        timer->setData(this);
        timer->start([](Timer *timer) {
            Socket *s = (Socket *) timer->getData();
            s->cancelTimeout();
            onTimeout(s);
        }, timeoutMs, 0);

        user = timer;
    }

    void cancelTimeout() {
        Timer *timer = (Timer *) getUserData();
        if (timer) {
            timer->stop();
            timer->close();
            user = nullptr;
        }
    }

    template <class STATE>
    static void sslIoHandler(Poll *p, int status, int events) {
        Socket *socket = (Socket *) p;

        if (status < 0) {
            STATE::onEnd((Socket *) p);
            return;
        }

        if (!socket->messageQueue.empty() && ((events & UV_WRITABLE) || SSL_want(socket->ssl) == SSL_READING)) {
            socket->cork(true);
            while (true) {
                Queue::Message *messagePtr = socket->messageQueue.front();
                int sent = SSL_write(socket->ssl, messagePtr->data, (int) messagePtr->length);
                if (sent == (ssize_t) messagePtr->length) {
                    if (messagePtr->callback) {
                        messagePtr->callback(p, messagePtr->callbackData, false, messagePtr->reserved);
                    }
                    socket->messageQueue.pop();
                    if (socket->messageQueue.empty()) {
                        if ((socket->state.poll & UV_WRITABLE) && SSL_want(socket->ssl) != SSL_WRITING) {
                            socket->change(socket->nodeData->loop, socket, socket->setPoll(UV_READABLE));
                        }
                        break;
                    }
                } else if (sent <= 0) {
                    switch (SSL_get_error(socket->ssl, sent)) {
                    case SSL_ERROR_WANT_READ:
                        // CHANGED error needs to be reset every time it has been set, otherwise the SSL_get_error
                        // will keep returning the same value and screwing up our switch-/if cases
                        ERR_clear_error();
                        break;
                    case SSL_ERROR_WANT_WRITE:
                        if ((socket->getPoll() & UV_WRITABLE) == 0) {
                            socket->change(socket->nodeData->loop, socket, socket->setPoll(socket->getPoll() | UV_WRITABLE));
                        }
                        // CHANGED error needs to be reset every time it has been set, otherwise the SSL_get_error
                        // will keep returning the same value and screwing up our switch-/if cases
                        ERR_clear_error();
                        break;
                    default:
                        STATE::onEnd((Socket *) p);
                        // CHANGED error needs to be reset every time it has been set, otherwise the SSL_get_error
                        // will keep returning the same value and screwing up our switch-/if cases
                        ERR_clear_error();
                        return;
                    }
                    break;
                }
            }
            socket->cork(false);
        }

        if (events & UV_READABLE) {
            do {
                int length = SSL_read(socket->ssl, socket->nodeData->recvBuffer, socket->nodeData->recvLength);
                if (length <= 0) {
                    switch (SSL_get_error(socket->ssl, length)) {
                    case SSL_ERROR_WANT_READ:
                        // CHANGED error needs to be reset every time it has been set, otherwise the SSL_get_error
                        // will keep returning the same value and screwing up our switch-/if cases
                        ERR_clear_error();
                        break;
                    case SSL_ERROR_WANT_WRITE:
                        if ((socket->getPoll() & UV_WRITABLE) == 0) {
                            socket->change(socket->nodeData->loop, socket, socket->setPoll(socket->getPoll() | UV_WRITABLE));
                        }
                        // CHANGED error needs to be reset every time it has been set, otherwise the SSL_get_error
                        // will keep returning the same value and screwing up our switch-/if cases
                        ERR_clear_error();
                        break;
                    default:
                        STATE::onEnd((Socket *) p);
                        // CHANGED error needs to be reset every time it has been set, otherwise the SSL_get_error
                        // will keep returning the same value and screwing up our switch-/if cases
                        ERR_clear_error();
                        return;
                    }
                    break;
                } else {
                    // Warning: onData can delete the socket! Happens when HttpSocket upgrades
                    socket = STATE::onData((Socket *) p, socket->nodeData->recvBuffer, length);
                    if (socket->isClosed() || socket->isShuttingDown()) {
                        return;
                    }
                }
            } while (SSL_pending(socket->ssl));
        }
    }

    template <class STATE>
    static void ioHandler(Poll *p, int status, int events) {
        Socket *socket = (Socket *) p;
        NodeData *nodeData = socket->nodeData;
        Context *netContext = nodeData->netContext;

        if (status < 0) {
            STATE::onEnd((Socket *) p);
            return;
        }

        if (events & UV_WRITABLE) {
            if (!socket->messageQueue.empty() && (events & UV_WRITABLE)) {
                socket->cork(true);
                while (true) {
                    Queue::Message *messagePtr = socket->messageQueue.front();
                    ssize_t sent = ::send(socket->getFd(), messagePtr->data, messagePtr->length, MSG_NOSIGNAL);
                    if (sent == (ssize_t) messagePtr->length) {
                        if (messagePtr->callback) {
                            messagePtr->callback(p, messagePtr->callbackData, false, messagePtr->reserved);
                        }
                        socket->messageQueue.pop();
                        if (socket->messageQueue.empty()) {
                            // todo, remove bit, don't set directly
                            socket->change(socket->nodeData->loop, socket, socket->setPoll(UV_READABLE));
                            break;
                        }
                    } else if (sent == UWS_SOCKET_ERROR) {
                        if (!netContext->wouldBlock()) {
                            STATE::onEnd((Socket *) p);
                            return;
                        }
                        break;
                    } else {
                        messagePtr->length -= sent;
                        messagePtr->data += sent;
                        break;
                    }
                }
                socket->cork(false);
            }
        }

        if (events & UV_READABLE) {
            int length = (int) recv(socket->getFd(), nodeData->recvBuffer, nodeData->recvLength, 0);
            if (length > 0) {
                STATE::onData((Socket *) p, nodeData->recvBuffer, length);
            } else if (length <= 0 || (length == UWS_SOCKET_ERROR && !netContext->wouldBlock())) {
                STATE::onEnd((Socket *) p);
            }
        }

    }

    template<class STATE>
    void setState() {
        if (ssl) {
            setCb(sslIoHandler<STATE>);
        } else {
            setCb(ioHandler<STATE>);
        }
    }

    bool hasEmptyQueue() {
        return messageQueue.empty();
    }

    void enqueue(Queue::Message *message) {
        messageQueue.push(message);
    }

    Queue::Message *allocMessage(size_t length, const char *data = 0) {
        Queue::Message *messagePtr = (Queue::Message *) new char[sizeof(Queue::Message) + length];
        messagePtr->length = length;
        messagePtr->data = ((char *) messagePtr) + sizeof(Queue::Message);
        Queue::initMessage(messagePtr);

        if (data) {
            memcpy((char *) messagePtr->data, data, messagePtr->length);
        }

        return messagePtr;
    }

    void freeMessage(Queue::Message *message) {
        delete [] (char *) message;
    }

    bool write(Queue::Message *message, bool &wasTransferred) {
        ssize_t sent = 0;
        if (messageQueue.empty()) {

            if (ssl) {
                if (message->prefixLength > 0) {
                    size_t totalLen = message->length;
                    size_t prefixLen = message->prefixLength;
                    uint8_t lenByte = static_cast<uint8_t>(message->data[1]) & 0x7F;
                    size_t headerLen = (lenByte < 126) ? 2 : ((lenByte == 126) ? 4 : 10);
                    size_t bodyLen = totalLen - headerLen - prefixLen;

                    // Combine [ws-header][prefix] on stack — at most 10 + 8 = 18 bytes.
                    char combined[18];
                    std::memcpy(combined, message->data, headerLen);
                    std::memcpy(combined + headerLen, message->prefix, prefixLen);
                    size_t combinedLen = headerLen + prefixLen;

                    ssize_t sent1 = SSL_write(ssl, combined, (int) combinedLen);
                    if (sent1 == (ssize_t) combinedLen) {
                        ssize_t sent2 = SSL_write(ssl, message->data + headerLen + prefixLen, (int) bodyLen);
                        if (sent2 == (ssize_t) bodyLen) {
                            wasTransferred = false;
                            return true;
                        } else if (sent2 <= 0) {
                            int err = SSL_get_error(ssl, (int) sent2);
                            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                                if ((getPoll() & UV_WRITABLE) == 0) {
                                    setPoll(getPoll() | UV_WRITABLE);
                                    changePoll(this);
                                }
                                ERR_clear_error();
                                // Body must be retried; flatten cursor past combined header+prefix.
                                if (!_convertPrefixMessageToContiguous(message, combinedLen, headerLen, prefixLen, bodyLen)) {
                                    return false;
                                }
                                // Fall through to common queue push.
                            } else {
                                ERR_clear_error();
                                return false;
                            }
                        } else {
                            // Partial body.
                            if (!_convertPrefixMessageToContiguous(message, combinedLen + sent2, headerLen, prefixLen, bodyLen)) {
                                return false;
                            }
                        }
                    } else if (sent1 <= 0) {
                        int err = SSL_get_error(ssl, (int) sent1);
                        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                            if ((getPoll() & UV_WRITABLE) == 0) {
                                setPoll(getPoll() | UV_WRITABLE);
                                changePoll(this);
                            }
                            ERR_clear_error();
                            // Whole message must be retried; flatten from offset 0.
                            if (!_convertPrefixMessageToContiguous(message, 0, headerLen, prefixLen, bodyLen)) {
                                return false;
                            }
                        } else {
                            ERR_clear_error();
                            return false;
                        }
                    } else {
                        // Partial header+prefix.
                        if (!_convertPrefixMessageToContiguous(message, sent1, headerLen, prefixLen, bodyLen)) {
                            return false;
                        }
                    }
                } else {
                    // Legacy single-buffer SSL path — UNCHANGED from existing code:
                    sent = SSL_write(ssl, message->data, (int) message->length);
                    if (sent == (ssize_t) message->length) {
                        wasTransferred = false;
                        return true;
                        // CHANGED this to <= 0 instead of < 0 as 0 is regarded as error too
                    } else if (sent <= 0) {
                        switch (SSL_get_error(ssl, (int) sent)) {
                        case SSL_ERROR_WANT_READ:
                            // CHANGED error needs to be reset every time it has been set, otherwise the SSL_get_error
                            // will keep returning the same value and screwing up our switch-/if cases
                            ERR_clear_error();
                            break;
                        case SSL_ERROR_WANT_WRITE:
                            if ((getPoll() & UV_WRITABLE) == 0) {
                                setPoll(getPoll() | UV_WRITABLE);
                                changePoll(this);
                            }
                            // CHANGED error needs to be reset every time it has been set, otherwise the SSL_get_error
                            // will keep returning the same value and screwing up our switch-/if cases
                            ERR_clear_error();
                            break;
                        default:
                            // CHANGED error needs to be reset every time it has been set, otherwise the SSL_get_error
                            // will keep returning the same value and screwing up our switch-/if cases
                            ERR_clear_error();
                            return false;
                        }
                    }
                }
            } else if (message->prefixLength > 0) {
                // Scatter-gather write for prefix-mode messages.
                // The prepared buffer has layout: [ws-header][reserved prefix slot][body]
                // and message->prefix carries the per-recipient prefix bytes.
                size_t totalLen = message->length;
                size_t prefixLen = message->prefixLength;
                uint8_t lenByte = static_cast<uint8_t>(message->data[1]) & 0x7F;
                size_t headerLen = (lenByte < 126) ? 2 : ((lenByte == 126) ? 4 : 10);
                size_t bodyLen = totalLen - headerLen - prefixLen;

                struct iovec iov[3];
                iov[0].iov_base = const_cast<char*>(message->data);
                iov[0].iov_len = headerLen;
                iov[1].iov_base = message->prefix;
                iov[1].iov_len = prefixLen;
                iov[2].iov_base = const_cast<char*>(message->data) + headerLen + prefixLen;
                iov[2].iov_len = bodyLen;

                ssize_t expectedTotal = static_cast<ssize_t>(headerLen + prefixLen + bodyLen);
                sent = ::writev(getFd(), iov, 3);
                if (sent == expectedTotal) {
                    wasTransferred = false;
                    return true;
                }
                if (sent == UWS_SOCKET_ERROR) {
                    if (!nodeData->netContext->wouldBlock()) {
                        return false;
                    }
                    // EAGAIN/would-block: 0 bytes sent. Must flatten before queueing because
                    // the legacy drain loop has no concept of prefixLength.
                    if (!_convertPrefixMessageToContiguous(message, 0, headerLen, prefixLen, bodyLen)) {
                        return false;
                    }
                    // Fall through to the common queue push at the bottom of write().
                } else if (sent >= 0) {
                    // Partial write (including sent==0). Flatten remainder.
                    if (!_convertPrefixMessageToContiguous(message, sent, headerLen, prefixLen, bodyLen)) {
                        return false;
                    }
                }

                if ((getPoll() & UV_WRITABLE) == 0) {
                    setPoll(getPoll() | UV_WRITABLE);
                    changePoll(this);
                }
            } else {
                // Legacy single-buffer non-SSL path (UNCHANGED from existing code):
                sent = ::send(getFd(), message->data, message->length, MSG_NOSIGNAL);
                if (sent == (ssize_t) message->length) {
                    wasTransferred = false;
                    return true;
                } else if (sent == UWS_SOCKET_ERROR) {
                    if (!nodeData->netContext->wouldBlock()) {
                        return false;
                    }
                } else {
                    message->length -= sent;
                    message->data += sent;
                }

                if ((getPoll() & UV_WRITABLE) == 0) {
                    setPoll(getPoll() | UV_WRITABLE);
                    changePoll(this);
                }
            }
        }
        messageQueue.push(message);
        wasTransferred = true;
        return true;
    }

    template <class T, class D>
    void sendTransformed(const char *message, size_t length, void(*callback)(void *socket, void *data, bool cancelled, void *reserved), void *callbackData, D transformData) {
        size_t estimatedLength = T::estimate(message, length) + sizeof(Queue::Message);

        if (hasEmptyQueue()) {
            if (estimatedLength <= uS::NodeData::preAllocMaxSize) {
                int memoryLength = (int) estimatedLength;
                int memoryIndex = nodeData->getMemoryBlockIndex(memoryLength);

                Queue::Message *messagePtr = (Queue::Message *) nodeData->getSmallMemoryBlock(memoryIndex);
                Queue::initMessage(messagePtr);
                messagePtr->data = ((char *) messagePtr) + sizeof(Queue::Message);
                messagePtr->length = T::transform(message, (char *) messagePtr->data, length, transformData);

                bool wasTransferred;
                if (write(messagePtr, wasTransferred)) {
                    if (!wasTransferred) {
                        nodeData->freeSmallMemoryBlock((char *) messagePtr, memoryIndex);
                        if (callback) {
                            callback(this, callbackData, false, nullptr);
                        }
                    } else {
                        messagePtr->callback = callback;
                        messagePtr->callbackData = callbackData;
                    }
                } else {
                    nodeData->freeSmallMemoryBlock((char *) messagePtr, memoryIndex);
                    if (callback) {
                        callback(this, callbackData, true, nullptr);
                    }
                }
            } else {
                Queue::Message *messagePtr = allocMessage(estimatedLength - sizeof(Queue::Message));
                messagePtr->length = T::transform(message, (char *) messagePtr->data, length, transformData);

                bool wasTransferred;
                if (write(messagePtr, wasTransferred)) {
                    if (!wasTransferred) {
                        freeMessage(messagePtr);
                        if (callback) {
                            callback(this, callbackData, false, nullptr);
                        }
                    } else {
                        messagePtr->callback = callback;
                        messagePtr->callbackData = callbackData;
                    }
                } else {
                    freeMessage(messagePtr);
                    if (callback) {
                        callback(this, callbackData, true, nullptr);
                    }
                }
            }
        } else {
            Queue::Message *messagePtr = allocMessage(estimatedLength - sizeof(Queue::Message));
            messagePtr->length = T::transform(message, (char *) messagePtr->data, length, transformData);
            messagePtr->callback = callback;
            messagePtr->callbackData = callbackData;
            enqueue(messagePtr);
        }
    }

private:
    // Flatten the unsent remainder of a scatter-gather prefix message into a contiguous
    // buffer owned via `flatOwned`. After this call, the message is legacy-compatible
    // (prefixLength == 0, data points at the flat buffer, length == remaining bytes,
    // flatOwned == data so pop() will free it).
    //
    // Returns false ONLY on allocation failure (treat as connection-broken).
    bool _convertPrefixMessageToContiguous(Queue::Message *message, ssize_t alreadySent,
                                           size_t headerLen, size_t prefixLen, size_t bodyLen) {
        size_t totalLen = headerLen + prefixLen + bodyLen;
        if (alreadySent < 0) alreadySent = 0;
        if (static_cast<size_t>(alreadySent) >= totalLen) {
            // Fully sent — caller treats this as "no need to queue".
            message->prefixLength = 0;
            message->length = 0;
            return true;
        }

        size_t remaining = totalLen - static_cast<size_t>(alreadySent);
        char *flat = nullptr;
        try {
            flat = new char[remaining];
        } catch (const std::bad_alloc&) {
            return false;
        }

        size_t pos = 0;
        size_t cursor = static_cast<size_t>(alreadySent);

        if (cursor < headerLen) {
            size_t take = headerLen - cursor;
            std::memcpy(flat + pos, message->data + cursor, take);
            pos += take;
            cursor += take;
        }
        if (cursor < headerLen + prefixLen) {
            size_t prefixStart = cursor - headerLen;
            size_t take = prefixLen - prefixStart;
            std::memcpy(flat + pos, message->prefix + prefixStart, take);
            pos += take;
            cursor += take;
        }
        if (cursor < totalLen) {
            size_t bodyStart = cursor - headerLen - prefixLen;
            size_t take = bodyLen - bodyStart;
            std::memcpy(flat + pos, message->data + headerLen + prefixLen + bodyStart, take);
        }

        message->data = flat;
        message->length = remaining;
        message->prefixLength = 0;
        message->flatOwned = flat;
        return true;
    }

public:
    Socket(NodeData *nodeData, Loop *loop, uv_os_sock_t fd, SSL *ssl) : Poll(loop, fd), ssl(ssl), nodeData(nodeData) {
        if (ssl) {
            // OpenSSL treats SOCKETs as int
            SSL_set_fd(ssl, (int) fd);
            SSL_set_mode(ssl, SSL_MODE_RELEASE_BUFFERS);
        }
    }

    NodeData *getNodeData() {
        return nodeData;
    }

    Poll *next = nullptr, *prev = nullptr;

    void *getUserData() {
        return user;
    }

    void setUserData(void *user) {
        this->user = user;
    }

    struct Address {
        unsigned int port;
        const char *address;
        const char *family;
    };

    Address getAddress();

    void setNoDelay(int enable) {
        setsockopt(getFd(), IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(int));
    }

    void cork(int enable) {
#if defined(TCP_CORK)
        // Linux & SmartOS have proper TCP_CORK
        setsockopt(getFd(), IPPROTO_TCP, TCP_CORK, &enable, sizeof(int));
#elif defined(TCP_NOPUSH)
        // Mac OS X & FreeBSD have TCP_NOPUSH
        setsockopt(getFd(), IPPROTO_TCP, TCP_NOPUSH, &enable, sizeof(int));
        if (!enable) {
            // Tested on OS X, FreeBSD situation is unclear
            ::send(getFd(), "", 0, MSG_NOSIGNAL);
        }
#endif
    }

    void shutdown() {
        if (ssl) {
            //todo: poll in/out - have the io_cb recall shutdown if failed
            SSL_shutdown(ssl);
        } else {
            ::shutdown(getFd(), SHUT_WR);
        }
    }

    template <class T>
    void closeSocket() {
        uv_os_sock_t fd = getFd();
        Context *netContext = nodeData->netContext;
        stop(nodeData->loop);
        netContext->closeSocket(fd);

        if (ssl) {
            SSL_free(ssl);
        }

        Poll::close(nodeData->loop, [](Poll *p) {
            delete (T *) p;
        });
    }

    bool isShuttingDown() {
        return state.shuttingDown;
    }

    friend class Node;
    friend struct NodeData;
};

struct ListenSocket : Socket {

    ListenSocket(NodeData *nodeData, Loop *loop, uv_os_sock_t fd, SSL *ssl) : Socket(nodeData, loop, fd, ssl) {

    }

    Timer *timer = nullptr;
    uS::TLS::Context sslContext;
};

}

#endif // SOCKET_UWS_H
