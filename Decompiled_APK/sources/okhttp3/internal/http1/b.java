package okhttp3.internal.http1;

import com.google.android.gms.internal.ads.C2007ea;
import kotlin.jvm.internal.Intrinsics;
import okio.C5091h;
import okio.E;
import okio.I;
import okio.p;
import okio.z;

/* loaded from: classes3.dex */
public final class b implements E {
    public final p a;
    public boolean b;
    public final /* synthetic */ C2007ea c;

    public b(C2007ea c2007ea) {
        this.c = c2007ea;
        this.a = new p(((z) c2007ea.e).a.h());
    }

    @Override // okio.E
    public final void L(C5091h source, long j) {
        Intrinsics.checkNotNullParameter(source, "source");
        if (this.b) {
            throw new IllegalStateException("closed");
        }
        if (j == 0) {
            return;
        }
        C2007ea c2007ea = this.c;
        z zVar = (z) c2007ea.e;
        if (zVar.c) {
            throw new IllegalStateException("closed");
        }
        zVar.b.r0(j);
        zVar.a();
        z zVar2 = (z) c2007ea.e;
        zVar2.H("\r\n");
        zVar2.L(source, j);
        zVar2.H("\r\n");
    }

    @Override // okio.E, java.io.Closeable, java.lang.AutoCloseable
    public final synchronized void close() {
        if (this.b) {
            return;
        }
        this.b = true;
        ((z) this.c.e).H("0\r\n\r\n");
        C2007ea.i(this.c, this.a);
        this.c.b = 3;
    }

    @Override // okio.E, java.io.Flushable
    public final synchronized void flush() {
        if (this.b) {
            return;
        }
        ((z) this.c.e).flush();
    }

    @Override // okio.E
    public final I h() {
        return this.a;
    }
}
