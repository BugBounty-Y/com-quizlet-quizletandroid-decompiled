package kotlinx.io;

import androidx.compose.animation.d0;
import java.io.EOFException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements i {
    public final c a;
    public boolean b;
    public final a c;

    public e(c source) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.a = source;
        this.c = new a();
    }

    @Override // kotlinx.io.d
    public final long A(a sink, long j) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (this.b) {
            throw new IllegalStateException("Source is closed.");
        }
        if (j < 0) {
            throw new IllegalArgumentException(d0.n(j, "byteCount: ").toString());
        }
        a aVar = this.c;
        if (aVar.c == 0 && this.a.A(aVar, 8192L) == -1) {
            return -1L;
        }
        return aVar.A(sink, Math.min(j, aVar.c));
    }

    @Override // kotlinx.io.i
    public final long G(a sink) {
        a aVar;
        Intrinsics.checkNotNullParameter(sink, "sink");
        long j = 0;
        while (true) {
            c cVar = this.a;
            aVar = this.c;
            if (cVar.A(aVar, 8192L) == -1) {
                break;
            }
            long j2 = aVar.c;
            if (j2 == 0) {
                j2 = 0;
            } else {
                g gVar = aVar.b;
                Intrinsics.d(gVar);
                if (gVar.c < 8192 && gVar.e) {
                    j2 -= r8 - gVar.b;
                }
            }
            if (j2 > 0) {
                j += j2;
                sink.l(aVar, j2);
            }
        }
        long j3 = aVar.c;
        if (j3 <= 0) {
            return j;
        }
        long j4 = j + j3;
        sink.l(aVar, j3);
        return j4;
    }

    @Override // kotlinx.io.i
    public final a c() {
        return this.c;
    }

    @Override // java.lang.AutoCloseable
    public final void close() throws EOFException {
        if (this.b) {
            return;
        }
        this.b = true;
        this.a.e = true;
        a aVar = this.c;
        aVar.skip(aVar.c);
    }

    @Override // kotlinx.io.i
    public final boolean e(long j) {
        a aVar;
        if (this.b) {
            throw new IllegalStateException("Source is closed.");
        }
        if (j < 0) {
            throw new IllegalArgumentException(d0.n(j, "byteCount: ").toString());
        }
        do {
            aVar = this.c;
            if (aVar.c >= j) {
                return true;
            }
        } while (this.a.A(aVar, 8192L) != -1);
        return false;
    }

    @Override // kotlinx.io.i
    public final int g0(int i, byte[] sink, int i2) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        j.a(sink.length, i, i2);
        a aVar = this.c;
        if (aVar.c == 0 && this.a.A(aVar, 8192L) == -1) {
            return -1;
        }
        return aVar.g0(i, sink, ((int) Math.min(i2 - i, aVar.c)) + i);
    }

    @Override // kotlinx.io.i
    public final void k(long j) throws EOFException {
        if (!e(j)) {
            throw new EOFException(d0.o(j, "Source doesn't contain required number of bytes (", ")."));
        }
    }

    @Override // kotlinx.io.i
    public final void n(a sink, long j) throws EOFException {
        a aVar = this.c;
        Intrinsics.checkNotNullParameter(sink, "sink");
        try {
            k(j);
            aVar.n(sink, j);
        } catch (EOFException e) {
            sink.l(aVar, aVar.c);
            throw e;
        }
    }

    @Override // kotlinx.io.i
    public final e peek() {
        if (this.b) {
            throw new IllegalStateException("Source is closed.");
        }
        c cVar = new c(this);
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        return new e(cVar);
    }

    @Override // kotlinx.io.i
    public final byte readByte() throws EOFException {
        k(1L);
        return this.c.readByte();
    }

    public final String toString() {
        return "buffered(" + this.a + ')';
    }

    @Override // kotlinx.io.i
    public final boolean u() {
        if (this.b) {
            throw new IllegalStateException("Source is closed.");
        }
        a aVar = this.c;
        return aVar.u() && this.a.A(aVar, 8192L) == -1;
    }
}
