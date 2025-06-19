package okio;

import java.io.IOException;
import java.io.OutputStream;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: okio.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5086c implements E {
    public final /* synthetic */ int a = 1;
    public final Object b;
    public final Object c;

    public C5086c(OutputStream out, I timeout) {
        Intrinsics.checkNotNullParameter(out, "out");
        Intrinsics.checkNotNullParameter(timeout, "timeout");
        this.b = out;
        this.c = timeout;
    }

    @Override // okio.E
    public final void L(C5091h source, long j) throws IOException {
        long j2;
        Object obj = this.b;
        Object obj2 = this.c;
        int i = this.a;
        Intrinsics.checkNotNullParameter(source, "source");
        switch (i) {
            case 0:
                AbstractC5085b.e(source.b, 0L, j);
                for (long j3 = j; j3 > 0; j3 -= j2) {
                    B b = source.a;
                    Intrinsics.d(b);
                    j2 = 0;
                    while (true) {
                        if (j2 < 65536) {
                            j2 += b.c - b.b;
                            if (j2 >= j3) {
                                j2 = j3;
                            } else {
                                b = b.f;
                                Intrinsics.d(b);
                            }
                        }
                    }
                    C5086c c5086c = (C5086c) obj2;
                    F f = (F) obj;
                    f.h();
                    try {
                        c5086c.L(source, j2);
                        Unit unit = Unit.a;
                        if (f.i()) {
                            throw f.k(null);
                        }
                    } catch (IOException e) {
                        if (!f.i()) {
                            throw e;
                        }
                        throw f.k(e);
                    } finally {
                        f.i();
                    }
                }
                return;
            default:
                AbstractC5085b.e(source.b, 0L, j);
                long j4 = j;
                while (j4 > 0) {
                    ((I) obj2).f();
                    B b2 = source.a;
                    Intrinsics.d(b2);
                    int iMin = (int) Math.min(j4, b2.c - b2.b);
                    ((OutputStream) obj).write(b2.a, b2.b, iMin);
                    int i2 = b2.b + iMin;
                    b2.b = i2;
                    long j5 = iMin;
                    j4 -= j5;
                    source.b -= j5;
                    if (i2 == b2.c) {
                        source.a = b2.a();
                        C.a(b2);
                    }
                }
                return;
        }
    }

    @Override // okio.E, java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                C5086c c5086c = (C5086c) this.c;
                F f = (F) obj;
                f.h();
                try {
                    c5086c.close();
                    Unit unit = Unit.a;
                    if (f.i()) {
                        throw f.k(null);
                    }
                    return;
                } catch (IOException e) {
                    if (!f.i()) {
                        throw e;
                    }
                    throw f.k(e);
                } finally {
                    f.i();
                }
            default:
                ((OutputStream) obj).close();
                return;
        }
    }

    @Override // okio.E, java.io.Flushable
    public final void flush() throws IOException {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                C5086c c5086c = (C5086c) this.c;
                F f = (F) obj;
                f.h();
                try {
                    c5086c.flush();
                    Unit unit = Unit.a;
                    if (f.i()) {
                        throw f.k(null);
                    }
                    return;
                } catch (IOException e) {
                    if (!f.i()) {
                        throw e;
                    }
                    throw f.k(e);
                } finally {
                    f.i();
                }
            default:
                ((OutputStream) obj).flush();
                return;
        }
    }

    @Override // okio.E
    public final I h() {
        switch (this.a) {
            case 0:
                return (F) this.b;
            default:
                return (I) this.c;
        }
    }

    public final String toString() {
        switch (this.a) {
            case 0:
                return "AsyncTimeout.sink(" + ((C5086c) this.c) + ')';
            default:
                return "sink(" + ((OutputStream) this.b) + ')';
        }
    }

    public C5086c(F f, C5086c c5086c) {
        this.b = f;
        this.c = c5086c;
    }
}
