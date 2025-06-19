package io.ktor.client.network.sockets;

import java.io.IOException;
import java.net.ConnectException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class ConnectTimeoutException extends ConnectException {
    public final IOException a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ConnectTimeoutException(String message, IOException iOException) {
        super(message);
        Intrinsics.checkNotNullParameter(message, "message");
        this.a = iOException;
    }

    @Override // java.lang.Throwable
    public final Throwable getCause() {
        return this.a;
    }
}
