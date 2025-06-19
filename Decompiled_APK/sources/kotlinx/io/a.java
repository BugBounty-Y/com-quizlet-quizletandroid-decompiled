package kotlinx.io;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import java.io.EOFException;
import java.io.Flushable;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements i, AutoCloseable, Flushable {
    public g a;
    public g b;
    public long c;

    @Override // kotlinx.io.d
    public final long A(a sink, long j) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (j < 0) {
            throw new IllegalArgumentException(d0.o(j, "byteCount (", ") < 0").toString());
        }
        long j2 = this.c;
        if (j2 == 0) {
            return -1L;
        }
        if (j > j2) {
            j = j2;
        }
        sink.l(this, j);
        return j;
    }

    @Override // kotlinx.io.i
    public final long G(a sink) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        long j = this.c;
        if (j > 0) {
            sink.l(this, j);
        }
        return j;
    }

    public final void a() {
        g gVar = this.a;
        Intrinsics.d(gVar);
        g gVar2 = gVar.f;
        this.a = gVar2;
        if (gVar2 == null) {
            this.b = null;
        } else {
            gVar2.g = null;
        }
        gVar.f = null;
        h.a(gVar);
    }

    @Override // kotlinx.io.i
    public final a c() {
        return this;
    }

    @Override // java.lang.AutoCloseable
    public final void close() {
    }

    public final /* synthetic */ void d() {
        g gVar = this.b;
        Intrinsics.d(gVar);
        g gVar2 = gVar.g;
        this.b = gVar2;
        if (gVar2 == null) {
            this.a = null;
        } else {
            gVar2.f = null;
        }
        gVar.g = null;
        h.a(gVar);
    }

    @Override // kotlinx.io.i
    public final boolean e(long j) {
        if (j >= 0) {
            return this.c >= j;
        }
        throw new IllegalArgumentException(d0.o(j, "byteCount: ", " < 0").toString());
    }

    public final void f(d source) {
        Intrinsics.checkNotNullParameter(source, "source");
        while (source.A(this, 8192L) != -1) {
        }
    }

    @Override // java.io.Flushable
    public final void flush() {
    }

    @Override // kotlinx.io.i
    public final int g0(int i, byte[] dst, int i2) {
        Intrinsics.checkNotNullParameter(dst, "sink");
        j.a(dst.length, i, i2);
        g gVar = this.a;
        if (gVar == null) {
            return -1;
        }
        int iMin = Math.min(i2 - i, gVar.b());
        Intrinsics.checkNotNullParameter(dst, "dst");
        int i3 = (i + iMin) - i;
        int i4 = gVar.b;
        C4930v.d(i, i4, i4 + i3, gVar.a, dst);
        gVar.b += i3;
        this.c -= iMin;
        if (j.c(gVar)) {
            a();
        }
        return iMin;
    }

    public final /* synthetic */ g i(int i) {
        if (i < 1 || i > 8192) {
            throw new IllegalArgumentException(AbstractC0147y.c(i, "unexpected capacity (", "), should be in range [1, 8192]").toString());
        }
        g gVar = this.b;
        if (gVar == null) {
            g gVarB = h.b();
            this.a = gVarB;
            this.b = gVarB;
            return gVarB;
        }
        if (gVar.c + i <= 8192 && gVar.e) {
            return gVar;
        }
        g gVarB2 = h.b();
        gVar.d(gVarB2);
        this.b = gVarB2;
        return gVarB2;
    }

    public final void j(int i, byte[] src) {
        Intrinsics.checkNotNullParameter(src, "source");
        int i2 = 0;
        j.a(src.length, 0, i);
        while (i2 < i) {
            g gVarI = i(1);
            int iMin = Math.min(i - i2, gVarI.a()) + i2;
            Intrinsics.checkNotNullParameter(src, "src");
            C4930v.d(gVarI.c, i2, iMin, src, gVarI.a);
            gVarI.c = (iMin - i2) + gVarI.c;
            i2 = iMin;
        }
        this.c += i;
    }

    @Override // kotlinx.io.i
    public final void k(long j) throws EOFException {
        if (j < 0) {
            throw new IllegalArgumentException(d0.n(j, "byteCount: ").toString());
        }
        if (this.c >= j) {
            return;
        }
        throw new EOFException("Buffer doesn't contain required number of bytes (size: " + this.c + ", required: " + j + ')');
    }

    public final void l(a source, long j) {
        g gVarB;
        Intrinsics.checkNotNullParameter(source, "source");
        if (source == this) {
            throw new IllegalArgumentException("source == this");
        }
        long j2 = source.c;
        if (0 > j2 || j2 < j || j < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.g(j2, "))", d0.t(j, "offset (0) and byteCount (", ") are not within the range [0..size(")));
        }
        while (j > 0) {
            Intrinsics.d(source.a);
            int i = 0;
            if (j < r0.b()) {
                g gVar = this.b;
                if (gVar != null && gVar.e) {
                    long j3 = gVar.c + j;
                    j jVar = gVar.d;
                    if (j3 - (jVar != null ? jVar.b() : false ? 0 : gVar.b) <= 8192) {
                        g gVar2 = source.a;
                        Intrinsics.d(gVar2);
                        gVar2.f(gVar, (int) j);
                        source.c -= j;
                        this.c += j;
                        return;
                    }
                }
                g gVar3 = source.a;
                Intrinsics.d(gVar3);
                int i2 = (int) j;
                if (i2 <= 0 || i2 > gVar3.c - gVar3.b) {
                    throw new IllegalArgumentException("byteCount out of range");
                }
                if (i2 >= 1024) {
                    gVarB = gVar3.e();
                } else {
                    gVarB = h.b();
                    int i3 = gVar3.b;
                    C4930v.d(0, i3, i3 + i2, gVar3.a, gVarB.a);
                }
                gVarB.c = gVarB.b + i2;
                gVar3.b += i2;
                g gVar4 = gVar3.g;
                if (gVar4 != null) {
                    gVar4.d(gVarB);
                } else {
                    gVarB.f = gVar3;
                    gVar3.g = gVarB;
                }
                source.a = gVarB;
            }
            g gVar5 = source.a;
            Intrinsics.d(gVar5);
            long jB = gVar5.b();
            g gVarC = gVar5.c();
            source.a = gVarC;
            if (gVarC == null) {
                source.b = null;
            }
            if (this.a == null) {
                this.a = gVar5;
                this.b = gVar5;
            } else {
                g gVar6 = this.b;
                Intrinsics.d(gVar6);
                gVar6.d(gVar5);
                g gVar7 = gVar5.g;
                if (gVar7 == null) {
                    throw new IllegalStateException("cannot compact");
                }
                if (gVar7.e) {
                    int i4 = gVar5.c - gVar5.b;
                    Intrinsics.d(gVar7);
                    int i5 = 8192 - gVar7.c;
                    g gVar8 = gVar5.g;
                    Intrinsics.d(gVar8);
                    j jVar2 = gVar8.d;
                    if (!(jVar2 != null ? jVar2.b() : false)) {
                        g gVar9 = gVar5.g;
                        Intrinsics.d(gVar9);
                        i = gVar9.b;
                    }
                    if (i4 <= i5 + i) {
                        g gVar10 = gVar5.g;
                        Intrinsics.d(gVar10);
                        gVar5.f(gVar10, i4);
                        if (gVar5.c() != null) {
                            throw new IllegalStateException("Check failed.");
                        }
                        h.a(gVar5);
                        gVar5 = gVar10;
                    }
                }
                this.b = gVar5;
                if (gVar5.g == null) {
                    this.a = gVar5;
                }
            }
            source.c -= jB;
            this.c += jB;
            j -= jB;
        }
    }

    @Override // kotlinx.io.i
    public final void n(a sink, long j) throws EOFException {
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (j < 0) {
            throw new IllegalArgumentException(d0.o(j, "byteCount (", ") < 0").toString());
        }
        long j2 = this.c;
        if (j2 >= j) {
            sink.l(this, j);
        } else {
            sink.l(this, j2);
            throw new EOFException(android.support.v4.media.session.a.g(this.c, " bytes were written.", d0.t(j, "Buffer exhausted before writing ", " bytes. Only ")));
        }
    }

    @Override // kotlinx.io.i
    public final e peek() {
        c cVar = new c(this);
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        return new e(cVar);
    }

    @Override // kotlinx.io.i
    public final byte readByte() throws EOFException {
        g gVar = this.a;
        if (gVar == null) {
            throw new EOFException("Buffer doesn't contain required number of bytes (size: " + this.c + ", required: 1)");
        }
        int iB = gVar.b();
        if (iB == 0) {
            a();
            return readByte();
        }
        int i = gVar.b;
        gVar.b = i + 1;
        byte b = gVar.a[i];
        this.c--;
        if (iB == 1) {
            a();
        }
        return b;
    }

    public final void skip(long j) throws EOFException {
        if (j < 0) {
            throw new IllegalArgumentException(d0.o(j, "byteCount (", ") < 0").toString());
        }
        long j2 = j;
        while (j2 > 0) {
            g gVar = this.a;
            if (gVar == null) {
                throw new EOFException(d0.o(j, "Buffer exhausted before skipping ", " bytes."));
            }
            int iMin = (int) Math.min(j2, gVar.c - gVar.b);
            long j3 = iMin;
            this.c -= j3;
            j2 -= j3;
            int i = gVar.b + iMin;
            gVar.b = i;
            if (i == gVar.c) {
                a();
            }
        }
    }

    public final String toString() {
        long j = this.c;
        if (j == 0) {
            return "Buffer(size=0)";
        }
        long j2 = 64;
        int iMin = (int) Math.min(j2, j);
        StringBuilder sb = new StringBuilder((iMin * 2) + (this.c > j2 ? 1 : 0));
        int i = 0;
        for (g segment = this.a; segment != null; segment = segment.f) {
            int i2 = 0;
            while (i < iMin && i2 < segment.b()) {
                int i3 = i2 + 1;
                Intrinsics.checkNotNullParameter(segment, "segment");
                byte b = segment.a[segment.b + i2];
                i++;
                char[] cArr = j.a;
                sb.append(cArr[(b >> 4) & 15]);
                sb.append(cArr[b & 15]);
                i2 = i3;
            }
        }
        if (this.c > j2) {
            sb.append((char) 8230);
        }
        return "Buffer(size=" + this.c + " hex=" + ((Object) sb) + ')';
    }

    @Override // kotlinx.io.i
    public final boolean u() {
        return this.c == 0;
    }
}
