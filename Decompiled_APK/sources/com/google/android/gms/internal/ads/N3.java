package com.google.android.gms.internal.ads;

import java.nio.ByteBuffer;

/* loaded from: classes2.dex */
public final class N3 extends AbstractC2692uC {
    static {
        AbstractC2457os.o(N3.class);
    }

    public N3(C1722Kd c1722Kd, C1728Ld c1728Ld) {
        ByteBuffer byteBuffer = c1722Kd.a;
        long jLimit = byteBuffer.limit();
        this.b = c1722Kd;
        this.d = c1722Kd.d();
        byteBuffer.position((int) (c1722Kd.d() + jLimit));
        this.e = c1722Kd.d();
        this.a = c1728Ld;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2692uC, java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2692uC
    public final String toString() {
        String string = this.b.toString();
        StringBuilder sb = new StringBuilder(String.valueOf(string).length() + 7);
        sb.append("model(");
        sb.append(string);
        sb.append(")");
        return sb.toString();
    }
}
