package okhttp3.internal.http2;

import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import okio.C5091h;
import okio.E;
import okio.I;

/* loaded from: classes3.dex */
public final class s implements E {
    public final boolean a;
    public final C5091h b = new C5091h();
    public boolean c;
    public final /* synthetic */ v d;

    public s(v vVar, boolean z) {
        this.d = vVar;
        this.a = z;
    }

    @Override // okio.E
    public final void L(C5091h source, long j) {
        Intrinsics.checkNotNullParameter(source, "source");
        byte[] bArr = okhttp3.internal.b.a;
        C5091h c5091h = this.b;
        c5091h.L(source, j);
        while (c5091h.b >= 16384) {
            a(false);
        }
    }

    /* JADX WARN: Finally extract failed */
    public final void a(boolean z) {
        long jMin;
        boolean z2;
        v vVar = this.d;
        synchronized (vVar) {
            try {
                vVar.l.h();
                while (vVar.e >= vVar.f && !this.a && !this.c) {
                    try {
                        synchronized (vVar) {
                            a aVar = vVar.m;
                            if (aVar != null) {
                                break;
                            } else {
                                vVar.k();
                            }
                        }
                    } catch (Throwable th) {
                        vVar.l.k();
                        throw th;
                    }
                }
                vVar.l.k();
                vVar.b();
                jMin = Math.min(vVar.f - vVar.e, this.b.b);
                vVar.e += jMin;
                z2 = z && jMin == this.b.b;
                Unit unit = Unit.a;
            } catch (Throwable th2) {
                throw th2;
            }
        }
        this.d.l.h();
        try {
            v vVar2 = this.d;
            vVar2.b.p(vVar2.a, z2, this.b, jMin);
        } finally {
            this.d.l.k();
        }
    }

    @Override // okio.E, java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        boolean z;
        v vVar = this.d;
        byte[] bArr = okhttp3.internal.b.a;
        synchronized (vVar) {
            if (this.c) {
                return;
            }
            synchronized (vVar) {
                z = vVar.m == null;
                Unit unit = Unit.a;
            }
            v vVar2 = this.d;
            if (!vVar2.j.a) {
                if (this.b.b > 0) {
                    while (this.b.b > 0) {
                        a(true);
                    }
                } else if (z) {
                    vVar2.b.p(vVar2.a, true, null, 0L);
                }
            }
            synchronized (this.d) {
                this.c = true;
                Unit unit2 = Unit.a;
            }
            this.d.b.flush();
            this.d.a();
        }
    }

    @Override // okio.E, java.io.Flushable
    public final void flush() {
        v vVar = this.d;
        byte[] bArr = okhttp3.internal.b.a;
        synchronized (vVar) {
            vVar.b();
            Unit unit = Unit.a;
        }
        while (this.b.b > 0) {
            a(false);
            this.d.b.flush();
        }
    }

    @Override // okio.E
    public final I h() {
        return this.d.l;
    }
}
