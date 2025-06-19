package io.ktor.websocket;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.InterfaceC5037v;

@Metadata
/* loaded from: classes3.dex */
public final class ProtocolViolationException extends Exception implements InterfaceC5037v {
    @Override // kotlinx.coroutines.InterfaceC5037v
    public final Throwable a() {
        Intrinsics.checkNotNullParameter(null, "violation");
        ProtocolViolationException protocolViolationException = new ProtocolViolationException();
        Intrinsics.checkNotNullParameter(protocolViolationException, "<this>");
        Intrinsics.checkNotNullParameter(this, "cause");
        protocolViolationException.initCause(this);
        return protocolViolationException;
    }

    @Override // java.lang.Throwable
    public final String getMessage() {
        return "Received illegal frame: null";
    }
}
