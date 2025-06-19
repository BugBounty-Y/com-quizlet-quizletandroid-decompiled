package okio;

import java.nio.ByteBuffer;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class z implements InterfaceC5092i {
    public final E a;
    public final C5091h b;
    public boolean c;

    public z(E sink) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        this.a = sink;
        this.b = new C5091h();
    }

    @Override // okio.InterfaceC5092i
    public final InterfaceC5092i F(int i, byte[] source) {
        Intrinsics.checkNotNullParameter(source, "source");
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        this.b.o0(source, 0, i);
        a();
        return this;
    }

    @Override // okio.InterfaceC5092i
    public final InterfaceC5092i H(String string) {
        Intrinsics.checkNotNullParameter(string, "string");
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        this.b.u0(string);
        a();
        return this;
    }

    @Override // okio.E
    public final void L(C5091h source, long j) {
        Intrinsics.checkNotNullParameter(source, "source");
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        this.b.L(source, j);
        a();
    }

    @Override // okio.InterfaceC5092i
    public final long M(G source) {
        Intrinsics.checkNotNullParameter(source, "source");
        long j = 0;
        while (true) {
            long jB0 = source.b0(this.b, 8192L);
            if (jB0 == -1) {
                return j;
            }
            j += jB0;
            a();
        }
    }

    @Override // okio.InterfaceC5092i
    public final InterfaceC5092i O(int i, int i2, String string) {
        Intrinsics.checkNotNullParameter(string, "string");
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        this.b.t0(i, i2, string);
        a();
        return this;
    }

    @Override // okio.InterfaceC5092i
    public final InterfaceC5092i X(byte[] source) {
        Intrinsics.checkNotNullParameter(source, "source");
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        this.b.n0(source);
        a();
        return this;
    }

    @Override // okio.InterfaceC5092i
    public final InterfaceC5092i Z(k byteString) {
        Intrinsics.checkNotNullParameter(byteString, "byteString");
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        this.b.m0(byteString);
        a();
        return this;
    }

    public final InterfaceC5092i a() {
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        C5091h c5091h = this.b;
        long jI = c5091h.i();
        if (jI > 0) {
            this.a.L(c5091h, jI);
        }
        return this;
    }

    @Override // okio.InterfaceC5092i
    public final C5091h c() {
        return this.b;
    }

    @Override // okio.E, java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        E e = this.a;
        if (this.c) {
            return;
        }
        try {
            C5091h c5091h = this.b;
            long j = c5091h.b;
            if (j > 0) {
                e.L(c5091h, j);
            }
            th = null;
        } catch (Throwable th) {
            th = th;
        }
        try {
            e.close();
        } catch (Throwable th2) {
            if (th == null) {
                th = th2;
            }
        }
        this.c = true;
        if (th != null) {
            throw th;
        }
    }

    public final InterfaceC5092i d(int i) {
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        this.b.s0(i);
        a();
        return this;
    }

    public final InterfaceC5092i f(int i) {
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        C5091h c5091h = this.b;
        B bL0 = c5091h.l0(2);
        int i2 = bL0.c;
        byte[] bArr = bL0.a;
        bArr[i2] = (byte) ((i >>> 8) & 255);
        bArr[i2 + 1] = (byte) (i & 255);
        bL0.c = i2 + 2;
        c5091h.b += 2;
        a();
        return this;
    }

    @Override // okio.InterfaceC5092i, okio.E, java.io.Flushable
    public final void flush() {
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        C5091h c5091h = this.b;
        long j = c5091h.b;
        E e = this.a;
        if (j > 0) {
            e.L(c5091h, j);
        }
        e.flush();
    }

    @Override // okio.E
    public final I h() {
        return this.a.h();
    }

    @Override // okio.InterfaceC5092i
    public final InterfaceC5092i h0(long j) {
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        this.b.q0(j);
        a();
        return this;
    }

    @Override // java.nio.channels.Channel
    public final boolean isOpen() {
        return !this.c;
    }

    public final String toString() {
        return "buffer(" + this.a + ')';
    }

    @Override // okio.InterfaceC5092i
    public final InterfaceC5092i v(int i) {
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        this.b.p0(i);
        a();
        return this;
    }

    @Override // java.nio.channels.WritableByteChannel
    public final int write(ByteBuffer source) {
        Intrinsics.checkNotNullParameter(source, "source");
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        int iWrite = this.b.write(source);
        a();
        return iWrite;
    }
}
