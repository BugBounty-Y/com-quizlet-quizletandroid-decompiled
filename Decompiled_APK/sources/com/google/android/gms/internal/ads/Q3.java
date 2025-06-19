package com.google.android.gms.internal.ads;

import java.nio.ByteBuffer;
import java.util.Date;

/* loaded from: classes2.dex */
public final class Q3 extends AbstractC2649tC {
    public int i;
    public Date j;
    public Date k;
    public long l;
    public long m;
    public double n;
    public float o;
    public C2864yC p;
    public long q;

    @Override // com.google.android.gms.internal.ads.AbstractC2649tC
    public final void c(ByteBuffer byteBuffer) {
        int i = byteBuffer.get();
        if (i < 0) {
            i += 256;
        }
        this.i = i;
        byteBuffer.get();
        byteBuffer.get();
        byteBuffer.get();
        if (!this.b) {
            d();
        }
        if (this.i == 1) {
            this.j = AbstractC2025es.k(AbstractC2096gb.H(byteBuffer));
            this.k = AbstractC2025es.k(AbstractC2096gb.H(byteBuffer));
            this.l = AbstractC2096gb.C(byteBuffer);
            this.m = AbstractC2096gb.H(byteBuffer);
        } else {
            this.j = AbstractC2025es.k(AbstractC2096gb.C(byteBuffer));
            this.k = AbstractC2025es.k(AbstractC2096gb.C(byteBuffer));
            this.l = AbstractC2096gb.C(byteBuffer);
            this.m = AbstractC2096gb.C(byteBuffer);
        }
        this.n = AbstractC2096gb.j(byteBuffer);
        byteBuffer.get(new byte[2]);
        this.o = ((short) ((r1[1] & 255) | ((short) (65280 & (r1[0] << 8))))) / 256.0f;
        byteBuffer.get();
        byteBuffer.get();
        AbstractC2096gb.C(byteBuffer);
        AbstractC2096gb.C(byteBuffer);
        this.p = new C2864yC(AbstractC2096gb.j(byteBuffer), AbstractC2096gb.j(byteBuffer), AbstractC2096gb.j(byteBuffer), AbstractC2096gb.j(byteBuffer), AbstractC2096gb.a(byteBuffer), AbstractC2096gb.a(byteBuffer), AbstractC2096gb.a(byteBuffer), AbstractC2096gb.j(byteBuffer), AbstractC2096gb.j(byteBuffer));
        byteBuffer.getInt();
        byteBuffer.getInt();
        byteBuffer.getInt();
        byteBuffer.getInt();
        byteBuffer.getInt();
        byteBuffer.getInt();
        this.q = AbstractC2096gb.C(byteBuffer);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MovieHeaderBox[creationTime=");
        sb.append(this.j);
        sb.append(";modificationTime=");
        sb.append(this.k);
        sb.append(";timescale=");
        sb.append(this.l);
        sb.append(";duration=");
        sb.append(this.m);
        sb.append(";rate=");
        sb.append(this.n);
        sb.append(";volume=");
        sb.append(this.o);
        sb.append(";matrix=");
        sb.append(this.p);
        sb.append(";nextTrackId=");
        return android.support.v4.media.session.a.g(this.q, "]", sb);
    }
}
