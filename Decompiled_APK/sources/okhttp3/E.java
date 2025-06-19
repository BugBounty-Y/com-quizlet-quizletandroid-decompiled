package okhttp3;

import kotlin.jvm.internal.Intrinsics;
import okio.InterfaceC5092i;

/* loaded from: classes3.dex */
public final class E extends F {
    public final /* synthetic */ w a;
    public final /* synthetic */ int b;
    public final /* synthetic */ byte[] c;

    public E(int i, w wVar, byte[] bArr) {
        this.a = wVar;
        this.b = i;
        this.c = bArr;
    }

    @Override // okhttp3.F
    public final long a() {
        return this.b;
    }

    @Override // okhttp3.F
    public final w b() {
        return this.a;
    }

    @Override // okhttp3.F
    public final void d(InterfaceC5092i sink) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        sink.F(this.b, this.c);
    }
}
