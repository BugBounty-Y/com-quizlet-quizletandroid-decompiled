package io.ktor.client.call;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class DoubleReceiveException extends IllegalStateException {
    public final String a;

    public DoubleReceiveException(b call) {
        Intrinsics.checkNotNullParameter(call, "call");
        this.a = "Response already received: " + call;
    }

    @Override // java.lang.Throwable
    public final String getMessage() {
        return this.a;
    }
}
