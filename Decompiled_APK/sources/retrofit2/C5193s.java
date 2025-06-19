package retrofit2;

import java.io.IOException;
import okio.AbstractC5085b;
import okio.InterfaceC5093j;

/* renamed from: retrofit2.s, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5193s extends okhttp3.J {
    public final okhttp3.J a;
    public final okio.A b;
    public IOException c;

    public C5193s(okhttp3.J j) {
        this.a = j;
        this.b = AbstractC5085b.c(new coil3.decode.b(this, j.f0()));
    }

    @Override // okhttp3.J
    public final long a() {
        return this.a.a();
    }

    @Override // okhttp3.J, java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        this.a.close();
    }

    @Override // okhttp3.J
    public final okhttp3.w d() {
        return this.a.d();
    }

    @Override // okhttp3.J
    public final InterfaceC5093j f0() {
        return this.b;
    }
}
