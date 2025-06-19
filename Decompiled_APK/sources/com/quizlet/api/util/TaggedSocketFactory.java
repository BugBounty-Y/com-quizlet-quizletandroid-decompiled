package com.quizlet.api.util;

import android.net.TrafficStats;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.SocketFactory;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class TaggedSocketFactory extends SocketFactory {

    @NotNull
    private final SocketFactory wrappedFactory;

    public TaggedSocketFactory(SocketFactory wrappedFactory) {
        Intrinsics.checkNotNullParameter(wrappedFactory, "wrappedFactory");
        this.wrappedFactory = wrappedFactory;
    }

    @Override // javax.net.SocketFactory
    public final Socket createSocket() throws IOException {
        Socket socketCreateSocket = this.wrappedFactory.createSocket();
        Intrinsics.checkNotNullExpressionValue(socketCreateSocket, "createSocket(...)");
        return socketCreateSocket;
    }

    @NotNull
    public final SocketFactory getWrappedFactory() {
        return this.wrappedFactory;
    }

    @Override // javax.net.SocketFactory
    public final Socket createSocket(String host, int i) throws IOException {
        Intrinsics.checkNotNullParameter(host, "host");
        Socket socketCreateSocket = this.wrappedFactory.createSocket(host, i);
        TrafficStats.tagSocket(socketCreateSocket);
        Intrinsics.d(socketCreateSocket);
        return socketCreateSocket;
    }

    @Override // javax.net.SocketFactory
    public final Socket createSocket(String host, int i, InetAddress localHost, int i2) throws IOException {
        Intrinsics.checkNotNullParameter(host, "host");
        Intrinsics.checkNotNullParameter(localHost, "localHost");
        Socket socketCreateSocket = this.wrappedFactory.createSocket(host, i, localHost, i2);
        TrafficStats.tagSocket(socketCreateSocket);
        Intrinsics.d(socketCreateSocket);
        return socketCreateSocket;
    }

    @Override // javax.net.SocketFactory
    public final Socket createSocket(InetAddress host, int i) throws IOException {
        Intrinsics.checkNotNullParameter(host, "host");
        Socket socketCreateSocket = this.wrappedFactory.createSocket(host, i);
        TrafficStats.tagSocket(socketCreateSocket);
        Intrinsics.d(socketCreateSocket);
        return socketCreateSocket;
    }

    @Override // javax.net.SocketFactory
    public final Socket createSocket(InetAddress address, int i, InetAddress localAddress, int i2) throws IOException {
        Intrinsics.checkNotNullParameter(address, "address");
        Intrinsics.checkNotNullParameter(localAddress, "localAddress");
        Socket socketCreateSocket = this.wrappedFactory.createSocket(address, i, localAddress, i2);
        TrafficStats.tagSocket(socketCreateSocket);
        Intrinsics.d(socketCreateSocket);
        return socketCreateSocket;
    }
}
