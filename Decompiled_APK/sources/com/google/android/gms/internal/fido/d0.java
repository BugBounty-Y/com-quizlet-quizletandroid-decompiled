package com.google.android.gms.internal.fido;

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.util.ArrayDeque;

/* loaded from: classes2.dex */
public final class d0 implements Closeable, AutoCloseable {
    public final ByteArrayInputStream a;
    public c0 b;
    public final byte[] c = new byte[8];
    public final com.google.firebase.platforminfo.c d = new com.google.firebase.platforminfo.c(22);

    public d0(ByteArrayInputStream byteArrayInputStream) {
        this.a = byteArrayInputStream;
    }

    public final long a() {
        q(Byte.MIN_VALUE);
        p();
        long jL = l();
        if (jL < 0) {
            throw new UnsupportedOperationException("the maximum supported array length is 9223372036854775807");
        }
        if (jL > 0) {
            ((ArrayDeque) this.d.a).push(Long.valueOf(jL));
        }
        return jL;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        this.a.close();
        this.d.p();
    }

    public final long d() {
        boolean z;
        i();
        byte b = this.b.a;
        if (b == 0) {
            z = true;
        } else {
            if (b != 32) {
                throw new IllegalStateException(android.support.v4.media.session.a.f((this.b.a >> 5) & 7, "expected major type 0 or 1 but found "));
            }
            z = false;
        }
        long jL = l();
        if (jL >= 0) {
            return z ? jL : ~jL;
        }
        throw new UnsupportedOperationException("the maximum supported unsigned/negative integer is 9223372036854775807");
    }

    public final long f() {
        q((byte) -96);
        p();
        long jL = l();
        if (jL < 0 || jL > 4611686018427387903L) {
            throw new UnsupportedOperationException("the maximum supported map length is 4611686018427387903L");
        }
        if (jL > 0) {
            ((ArrayDeque) this.d.a).push(Long.valueOf(jL + jL));
        }
        return jL;
    }

    /* JADX WARN: Code restructure failed: missing block: B:41:0x0098, code lost:
    
        if (r0 != (-2)) goto L42;
     */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0096  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00da  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.internal.fido.c0 i() {
        /*
            Method dump skipped, instructions count: 234
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.fido.d0.i():com.google.android.gms.internal.fido.c0");
    }

    public final boolean j() {
        q((byte) -32);
        if (this.b.b > 24) {
            throw new IllegalStateException("expected simple value");
        }
        int iL = (int) l();
        if (iL == 20) {
            return false;
        }
        if (iL == 21) {
            return true;
        }
        throw new IllegalStateException("expected FALSE or TRUE");
    }

    public final long l() throws IOException {
        byte b = this.b.b;
        if (b < 24) {
            long j = b;
            this.b = null;
            return j;
        }
        if (b == 24) {
            int i = this.a.read();
            if (i == -1) {
                throw new EOFException();
            }
            this.b = null;
            return i & 255;
        }
        byte[] bArr = this.c;
        if (b == 25) {
            r(2, bArr);
            return (bArr[1] & 255) | ((bArr[0] & 255) << 8);
        }
        if (b == 26) {
            r(4, bArr);
            long j2 = bArr[0];
            long j3 = bArr[1];
            return (bArr[3] & 255) | ((j3 & 255) << 16) | ((j2 & 255) << 24) | ((bArr[2] & 255) << 8);
        }
        if (b != 27) {
            c0 c0Var = this.b;
            throw new IOException(androidx.compose.animation.d0.p("invalid additional information ", c0Var.b, " for major type ", (c0Var.a >> 5) & 7));
        }
        r(8, bArr);
        long j4 = bArr[0];
        long j5 = bArr[1];
        long j6 = bArr[2];
        long j7 = bArr[3];
        return (bArr[7] & 255) | ((j4 & 255) << 56) | ((j5 & 255) << 48) | ((j6 & 255) << 40) | ((j7 & 255) << 32) | ((bArr[4] & 255) << 24) | ((bArr[5] & 255) << 16) | ((bArr[6] & 255) << 8);
    }

    public final void p() {
        i();
        if (this.b.b == 31) {
            throw new IllegalStateException(android.support.v4.media.session.a.f(this.b.b, "expected definite length but found "));
        }
    }

    public final void q(byte b) {
        i();
        if (this.b.a != b) {
            throw new IllegalStateException(androidx.compose.animation.d0.p("expected major type ", (b >> 5) & 7, " but found ", (this.b.a >> 5) & 7));
        }
    }

    public final void r(int i, byte[] bArr) throws IOException {
        int i2 = 0;
        while (i2 != i) {
            int i3 = this.a.read(bArr, i2, i - i2);
            if (i3 == -1) {
                throw new EOFException();
            }
            i2 += i3;
        }
        this.b = null;
    }

    public final byte[] y() {
        p();
        long jL = l();
        if (jL < 0 || jL > 2147483647L) {
            throw new UnsupportedOperationException("the maximum supported byte/text string length is 2147483647 bytes");
        }
        if (this.a.available() < jL) {
            throw new EOFException();
        }
        int i = (int) jL;
        byte[] bArr = new byte[i];
        r(i, bArr);
        return bArr;
    }
}
