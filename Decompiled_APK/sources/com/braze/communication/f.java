package com.braze.communication;

import androidx.collection.Y;
import com.braze.support.BrazeLogger;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;

/* loaded from: classes.dex */
public final class f extends SSLSocketFactory {
    public final SSLSocketFactory a;

    public f() throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sSLContext = SSLContext.getInstance("TLS");
        sSLContext.init(null, null, null);
        this.a = sSLContext.getSocketFactory();
    }

    public final Socket a(Socket socket) {
        if (socket instanceof SSLSocket) {
            ArrayList arrayList = new ArrayList();
            SSLSocket sSLSocket = (SSLSocket) socket;
            Y yF = O.f(sSLSocket.getSupportedProtocols());
            while (yF.hasNext()) {
                String str = (String) yF.next();
                if (!Intrinsics.b(str, "SSLv3")) {
                    Intrinsics.d(str);
                    arrayList.add(str);
                }
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new k(0, arrayList), 6, (Object) null);
            sSLSocket.setEnabledProtocols((String[]) arrayList.toArray(new String[0]));
        }
        return socket;
    }

    @Override // javax.net.SocketFactory
    public final Socket createSocket() throws IOException {
        Socket socketCreateSocket = this.a.createSocket();
        Intrinsics.checkNotNullExpressionValue(socketCreateSocket, "createSocket(...)");
        return a(socketCreateSocket);
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public final String[] getDefaultCipherSuites() {
        String[] defaultCipherSuites = this.a.getDefaultCipherSuites();
        Intrinsics.checkNotNullExpressionValue(defaultCipherSuites, "getDefaultCipherSuites(...)");
        return defaultCipherSuites;
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public final String[] getSupportedCipherSuites() {
        String[] supportedCipherSuites = this.a.getSupportedCipherSuites();
        Intrinsics.checkNotNullExpressionValue(supportedCipherSuites, "getSupportedCipherSuites(...)");
        return supportedCipherSuites;
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public final Socket createSocket(Socket socket, String host, int i, boolean z) throws IOException {
        Intrinsics.checkNotNullParameter(socket, "socket");
        Intrinsics.checkNotNullParameter(host, "host");
        Socket socketCreateSocket = this.a.createSocket(socket, host, i, z);
        Intrinsics.checkNotNullExpressionValue(socketCreateSocket, "createSocket(...)");
        return a(socketCreateSocket);
    }

    @Override // javax.net.SocketFactory
    public final Socket createSocket(String host, int i) throws IOException {
        Intrinsics.checkNotNullParameter(host, "host");
        Socket socketCreateSocket = this.a.createSocket(host, i);
        Intrinsics.checkNotNullExpressionValue(socketCreateSocket, "createSocket(...)");
        return a(socketCreateSocket);
    }

    @Override // javax.net.SocketFactory
    public final Socket createSocket(String host, int i, InetAddress localHost, int i2) throws IOException {
        Intrinsics.checkNotNullParameter(host, "host");
        Intrinsics.checkNotNullParameter(localHost, "localHost");
        Socket socketCreateSocket = this.a.createSocket(host, i, localHost, i2);
        Intrinsics.checkNotNullExpressionValue(socketCreateSocket, "createSocket(...)");
        return a(socketCreateSocket);
    }

    @Override // javax.net.SocketFactory
    public final Socket createSocket(InetAddress host, int i) throws IOException {
        Intrinsics.checkNotNullParameter(host, "host");
        Socket socketCreateSocket = this.a.createSocket(host, i);
        Intrinsics.checkNotNullExpressionValue(socketCreateSocket, "createSocket(...)");
        return a(socketCreateSocket);
    }

    @Override // javax.net.SocketFactory
    public final Socket createSocket(InetAddress address, int i, InetAddress localAddress, int i2) throws IOException {
        Intrinsics.checkNotNullParameter(address, "address");
        Intrinsics.checkNotNullParameter(localAddress, "localAddress");
        Socket socketCreateSocket = this.a.createSocket(address, i, localAddress, i2);
        Intrinsics.checkNotNullExpressionValue(socketCreateSocket, "createSocket(...)");
        return a(socketCreateSocket);
    }

    public static final String a(List list) {
        return "Enabling SSL protocols: " + list;
    }
}
