package com.google.android.gms.internal.ads;

import java.nio.ByteBuffer;

/* loaded from: classes2.dex */
public class MC extends androidx.sqlite.db.b {
    public C1832aG c;
    public final LC d;
    public ByteBuffer e;
    public boolean f;
    public long g;
    public ByteBuffer h;
    public final int i;

    static {
        E3.a("media3.decoder");
    }

    public MC(int i) {
        super(2);
        this.d = new LC();
        this.i = i;
    }

    public void v() {
        this.b = 0;
        ByteBuffer byteBuffer = this.e;
        if (byteBuffer != null) {
            byteBuffer.clear();
        }
        ByteBuffer byteBuffer2 = this.h;
        if (byteBuffer2 != null) {
            byteBuffer2.clear();
        }
        this.f = false;
    }

    public final void w(int i) {
        ByteBuffer byteBuffer = this.e;
        if (byteBuffer == null) {
            this.e = z(i);
            return;
        }
        int iCapacity = byteBuffer.capacity();
        int iPosition = byteBuffer.position();
        int i2 = i + iPosition;
        if (iCapacity >= i2) {
            this.e = byteBuffer;
            return;
        }
        ByteBuffer byteBufferZ = z(i2);
        byteBufferZ.order(byteBuffer.order());
        if (iPosition > 0) {
            byteBuffer.flip();
            byteBufferZ.put(byteBuffer);
        }
        this.e = byteBufferZ;
    }

    public final void x() {
        ByteBuffer byteBuffer = this.e;
        if (byteBuffer != null) {
            byteBuffer.flip();
        }
        ByteBuffer byteBuffer2 = this.h;
        if (byteBuffer2 != null) {
            byteBuffer2.flip();
        }
    }

    public final boolean y() {
        return s(1073741824);
    }

    public final ByteBuffer z(int i) {
        int i2 = this.i;
        if (i2 == 1) {
            return ByteBuffer.allocate(i);
        }
        if (i2 == 2) {
            return ByteBuffer.allocateDirect(i);
        }
        ByteBuffer byteBuffer = this.e;
        throw new zzho(android.support.v4.media.session.a.j("Buffer too small (", byteBuffer == null ? 0 : byteBuffer.capacity(), " < ", ")", i));
    }
}
