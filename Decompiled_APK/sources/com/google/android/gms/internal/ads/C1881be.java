package com.google.android.gms.internal.ads;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.ads.be, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1881be extends SSLSocketFactory {
    public final /* synthetic */ int a;
    public final SSLSocketFactory b;
    public final Object c;

    public C1881be(C1924ce c1924ce) {
        this.a = 0;
        this.c = c1924ce;
        this.b = (SSLSocketFactory) SSLSocketFactory.getDefault();
    }

    public void a(Socket socket) {
        if (socket instanceof SSLSocket) {
            ((SSLSocket) socket).setEnabledProtocols((String[]) this.c);
        }
    }

    public void b(Socket socket) throws SocketException {
        C1924ce c1924ce = (C1924ce) this.c;
        int i = c1924ce.r;
        if (i > 0) {
            socket.setReceiveBufferSize(i);
        }
        c1924ce.s.add(socket);
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket() throws IOException {
        switch (this.a) {
            case 1:
                Socket socketCreateSocket = this.b.createSocket();
                Intrinsics.checkNotNullExpressionValue(socketCreateSocket, "internalSSLSocketFactory.createSocket()");
                a(socketCreateSocket);
                return socketCreateSocket;
            default:
                return super.createSocket();
        }
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public final String[] getDefaultCipherSuites() {
        switch (this.a) {
            case 0:
                return this.b.getDefaultCipherSuites();
            default:
                String[] defaultCipherSuites = this.b.getDefaultCipherSuites();
                Intrinsics.checkNotNullExpressionValue(defaultCipherSuites, "internalSSLSocketFactory.defaultCipherSuites");
                return defaultCipherSuites;
        }
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public final String[] getSupportedCipherSuites() {
        switch (this.a) {
            case 0:
                return this.b.getSupportedCipherSuites();
            default:
                String[] supportedCipherSuites = this.b.getSupportedCipherSuites();
                Intrinsics.checkNotNullExpressionValue(supportedCipherSuites, "internalSSLSocketFactory.supportedCipherSuites");
                return supportedCipherSuites;
        }
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public final Socket createSocket(Socket s, String host, int i, boolean z) throws IOException {
        switch (this.a) {
            case 0:
                Socket socketCreateSocket = this.b.createSocket(s, host, i, z);
                b(socketCreateSocket);
                return socketCreateSocket;
            default:
                Intrinsics.checkNotNullParameter(s, "s");
                Intrinsics.checkNotNullParameter(host, "host");
                Socket socketCreateSocket2 = this.b.createSocket(s, host, i, z);
                Intrinsics.checkNotNullExpressionValue(socketCreateSocket2, "internalSSLSocketFactory…s, host, port, autoClose)");
                a(socketCreateSocket2);
                return socketCreateSocket2;
        }
    }

    public C1881be(String[] versions) throws NoSuchAlgorithmException, KeyManagementException {
        this.a = 1;
        Intrinsics.checkNotNullParameter(versions, "versions");
        this.c = versions;
        SSLContext sSLContext = SSLContext.getInstance("TLS");
        sSLContext.init(null, null, null);
        SSLSocketFactory socketFactory = sSLContext.getSocketFactory();
        Intrinsics.checkNotNullExpressionValue(socketFactory, "context.socketFactory");
        this.b = socketFactory;
    }

    @Override // javax.net.SocketFactory
    public final Socket createSocket(String host, int i) throws IOException {
        switch (this.a) {
            case 0:
                Socket socketCreateSocket = this.b.createSocket(host, i);
                b(socketCreateSocket);
                return socketCreateSocket;
            default:
                Intrinsics.checkNotNullParameter(host, "host");
                Socket socketCreateSocket2 = this.b.createSocket(host, i);
                Intrinsics.checkNotNullExpressionValue(socketCreateSocket2, "internalSSLSocketFactory.createSocket(host, port)");
                a(socketCreateSocket2);
                return socketCreateSocket2;
        }
    }

    @Override // javax.net.SocketFactory
    public final Socket createSocket(String host, int i, InetAddress localHost, int i2) throws IOException {
        switch (this.a) {
            case 0:
                Socket socketCreateSocket = this.b.createSocket(host, i, localHost, i2);
                b(socketCreateSocket);
                return socketCreateSocket;
            default:
                Intrinsics.checkNotNullParameter(host, "host");
                Intrinsics.checkNotNullParameter(localHost, "localHost");
                Socket socketCreateSocket2 = this.b.createSocket(host, i, localHost, i2);
                Intrinsics.checkNotNullExpressionValue(socketCreateSocket2, "internalSSLSocketFactory…  localPort\n            )");
                a(socketCreateSocket2);
                return socketCreateSocket2;
        }
    }

    @Override // javax.net.SocketFactory
    public final Socket createSocket(InetAddress host, int i) throws IOException {
        switch (this.a) {
            case 0:
                Socket socketCreateSocket = this.b.createSocket(host, i);
                b(socketCreateSocket);
                return socketCreateSocket;
            default:
                Intrinsics.checkNotNullParameter(host, "host");
                Socket socketCreateSocket2 = this.b.createSocket(host, i);
                Intrinsics.checkNotNullExpressionValue(socketCreateSocket2, "internalSSLSocketFactory.createSocket(host, port)");
                a(socketCreateSocket2);
                return socketCreateSocket2;
        }
    }

    @Override // javax.net.SocketFactory
    public final Socket createSocket(InetAddress address, int i, InetAddress localAddress, int i2) throws IOException {
        switch (this.a) {
            case 0:
                Socket socketCreateSocket = this.b.createSocket(address, i, localAddress, i2);
                b(socketCreateSocket);
                return socketCreateSocket;
            default:
                Intrinsics.checkNotNullParameter(address, "address");
                Intrinsics.checkNotNullParameter(localAddress, "localAddress");
                Socket socketCreateSocket2 = this.b.createSocket(address, i, localAddress, i2);
                Intrinsics.checkNotNullExpressionValue(socketCreateSocket2, "internalSSLSocketFactory…  localPort\n            )");
                a(socketCreateSocket2);
                return socketCreateSocket2;
        }
    }
}
