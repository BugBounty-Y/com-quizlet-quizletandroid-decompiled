package okio;

import androidx.compose.animation.d0;
import java.io.IOException;
import java.io.InputStream;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: okio.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5087d implements G {
    public final /* synthetic */ int a = 1;
    public final Object b;
    public final Object c;

    public C5087d(InputStream input, I timeout) {
        Intrinsics.checkNotNullParameter(input, "input");
        Intrinsics.checkNotNullParameter(timeout, "timeout");
        this.b = input;
        this.c = timeout;
    }

    @Override // okio.G
    public final long b0(C5091h sink, long j) throws IOException {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(sink, "sink");
                C5087d c5087d = (C5087d) this.c;
                F f = (F) this.b;
                f.h();
                try {
                    long jB0 = c5087d.b0(sink, j);
                    if (f.i()) {
                        throw f.k(null);
                    }
                    return jB0;
                } catch (IOException e) {
                    if (f.i()) {
                        throw f.k(e);
                    }
                    throw e;
                } finally {
                    f.i();
                }
            default:
                Intrinsics.checkNotNullParameter(sink, "sink");
                if (j == 0) {
                    return 0L;
                }
                if (j < 0) {
                    throw new IllegalArgumentException(d0.n(j, "byteCount < 0: ").toString());
                }
                try {
                    ((I) this.c).f();
                    B bL0 = sink.l0(1);
                    int i = ((InputStream) this.b).read(bL0.a, bL0.c, (int) Math.min(j, 8192 - bL0.c));
                    if (i == -1) {
                        if (bL0.b == bL0.c) {
                            sink.a = bL0.a();
                            C.a(bL0);
                        }
                        return -1L;
                    }
                    bL0.c += i;
                    long j2 = i;
                    sink.b += j2;
                    return j2;
                } catch (AssertionError e2) {
                    if (AbstractC5085b.f(e2)) {
                        throw new IOException(e2);
                    }
                    throw e2;
                }
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                C5087d c5087d = (C5087d) this.c;
                F f = (F) obj;
                f.h();
                try {
                    c5087d.close();
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
                ((InputStream) obj).close();
                return;
        }
    }

    @Override // okio.G
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
                return "AsyncTimeout.source(" + ((C5087d) this.c) + ')';
            default:
                return "source(" + ((InputStream) this.b) + ')';
        }
    }

    public C5087d(F f, C5087d c5087d) {
        this.b = f;
        this.c = c5087d;
    }
}
