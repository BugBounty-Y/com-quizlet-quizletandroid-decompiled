package io.ktor.client.engine.okhttp;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.InterfaceC5037v;

@Metadata
/* loaded from: classes3.dex */
public final class UnsupportedFrameTypeException extends IllegalArgumentException implements InterfaceC5037v {
    @Override // kotlinx.coroutines.InterfaceC5037v
    public final Throwable a() {
        Intrinsics.checkNotNullParameter(null, "frame");
        new UnsupportedFrameTypeException("Unsupported frame type: " + ((Object) null));
        throw null;
    }
}
