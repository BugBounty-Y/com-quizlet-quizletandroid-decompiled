package okhttp3.internal.http2;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends g {
    @Override // okhttp3.internal.http2.g
    public final void b(v stream) {
        Intrinsics.checkNotNullParameter(stream, "stream");
        stream.c(a.REFUSED_STREAM, null);
    }
}
