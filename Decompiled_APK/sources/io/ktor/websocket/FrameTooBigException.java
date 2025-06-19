package io.ktor.websocket;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.InterfaceC5037v;

@Metadata
/* loaded from: classes3.dex */
public final class FrameTooBigException extends Exception implements InterfaceC5037v {
    @Override // kotlinx.coroutines.InterfaceC5037v
    public final Throwable a() {
        FrameTooBigException frameTooBigException = new FrameTooBigException();
        Intrinsics.checkNotNullParameter(frameTooBigException, "<this>");
        Intrinsics.checkNotNullParameter(this, "cause");
        frameTooBigException.initCause(this);
        return frameTooBigException;
    }

    @Override // java.lang.Throwable
    public final String getMessage() {
        return "Frame is too big: 0";
    }
}
