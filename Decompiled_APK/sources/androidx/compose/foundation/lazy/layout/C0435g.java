package androidx.compose.foundation.lazy.layout;

/* renamed from: androidx.compose.foundation.lazy.layout.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0435g {
    public final int a;
    public final int b;
    public final InterfaceC0447t c;

    public C0435g(int i, int i2, InterfaceC0447t interfaceC0447t) {
        this.a = i;
        this.b = i2;
        this.c = interfaceC0447t;
        if (i < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "startIndex should be >= 0, but was ").toString());
        }
        if (i2 <= 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "size should be >0, but was ").toString());
        }
    }
}
