package com.google.android.gms.internal.ads;

import java.io.Closeable;
import java.nio.ByteBuffer;

/* renamed from: com.google.android.gms.internal.ads.Kd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1722Kd implements Closeable {
    public final ByteBuffer a;

    public C1722Kd(ByteBuffer byteBuffer) {
        this.a = byteBuffer.duplicate();
    }

    public final int a(ByteBuffer byteBuffer) {
        ByteBuffer byteBuffer2 = this.a;
        if (byteBuffer2.remaining() == 0 && byteBuffer.remaining() > 0) {
            return -1;
        }
        int iMin = Math.min(byteBuffer.remaining(), byteBuffer2.remaining());
        byte[] bArr = new byte[iMin];
        byteBuffer2.get(bArr);
        byteBuffer.put(bArr);
        return iMin;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
    }

    public final long d() {
        return this.a.position();
    }
}
