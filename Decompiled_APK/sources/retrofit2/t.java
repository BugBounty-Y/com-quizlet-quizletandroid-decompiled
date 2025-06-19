package retrofit2;

import okio.InterfaceC5093j;

/* loaded from: classes3.dex */
public final class t extends okhttp3.J {
    public final okhttp3.w a;
    public final long b;

    public t(okhttp3.w wVar, long j) {
        this.a = wVar;
        this.b = j;
    }

    @Override // okhttp3.J
    public final long a() {
        return this.b;
    }

    @Override // okhttp3.J
    public final okhttp3.w d() {
        return this.a;
    }

    @Override // okhttp3.J
    public final InterfaceC5093j f0() {
        throw new IllegalStateException("Cannot read raw response body of a converted body.");
    }
}
