package okhttp3.internal.http1;

import com.google.android.gms.internal.ads.C2007ea;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.internal.connection.i;
import okhttp3.s;

/* loaded from: classes3.dex */
public final class c extends a {
    public final s d;
    public long e;
    public boolean f;
    public final /* synthetic */ C2007ea g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(C2007ea c2007ea, s url) {
        super(c2007ea);
        Intrinsics.checkNotNullParameter(url, "url");
        this.g = c2007ea;
        this.d = url;
        this.e = -1L;
        this.f = true;
    }

    /* JADX WARN: Code restructure failed: missing block: B:29:0x0093, code lost:
    
        if (r10.f == false) goto L30;
     */
    @Override // okhttp3.internal.http1.a, okio.G
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long b0(okio.C5091h r11, long r12) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 250
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: okhttp3.internal.http1.c.b0(okio.h, long):long");
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        if (this.b) {
            return;
        }
        if (this.f) {
            TimeUnit timeUnit = TimeUnit.MILLISECONDS;
            if (!okhttp3.internal.b.i(this)) {
                ((i) this.g.d).k();
                a();
            }
        }
        this.b = true;
    }
}
