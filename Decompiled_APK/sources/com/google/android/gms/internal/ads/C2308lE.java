package com.google.android.gms.internal.ads;

import java.nio.ByteBuffer;
import java.util.Arrays;

/* renamed from: com.google.android.gms.internal.ads.lE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2308lE extends AbstractC1754Pf {
    public int[] i;
    public int[] j;

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final void c(ByteBuffer byteBuffer) {
        int[] iArr = this.j;
        iArr.getClass();
        int iPosition = byteBuffer.position();
        int iLimit = byteBuffer.limit();
        ByteBuffer byteBufferE = e(((iLimit - iPosition) / this.b.d) * this.c.d);
        while (iPosition < iLimit) {
            for (int i : iArr) {
                int iO = (Yo.o(this.b.c) * i) + iPosition;
                int i2 = this.b.c;
                if (i2 == 2) {
                    byteBufferE.putShort(byteBuffer.getShort(iO));
                } else {
                    if (i2 != 4) {
                        throw new IllegalStateException(android.support.v4.media.session.a.f(i2, "Unexpected encoding: "));
                    }
                    byteBufferE.putFloat(byteBuffer.getFloat(iO));
                }
            }
            iPosition += this.b.d;
        }
        byteBuffer.position(iLimit);
        byteBufferE.flip();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1754Pf
    public final C2229jf d(C2229jf c2229jf) throws zzcm {
        int[] iArr = this.i;
        if (iArr == null) {
            return C2229jf.e;
        }
        int i = c2229jf.c;
        if (i != 2 && i != 4) {
            throw new zzcm("Unhandled input format:", c2229jf);
        }
        int length = iArr.length;
        int i2 = c2229jf.b;
        boolean z = i2 != length;
        int i3 = 0;
        while (true) {
            int length2 = iArr.length;
            if (i3 >= length2) {
                return z ? new C2229jf(c2229jf.a, length2, i) : C2229jf.e;
            }
            int i4 = iArr[i3];
            if (i4 >= i2) {
                throw new zzcm(android.support.v4.media.session.a.B("Channel map (", Arrays.toString(iArr), ") trying to access non-existent input channel."), c2229jf);
            }
            z |= i4 != i3;
            i3++;
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1754Pf
    public final void i() {
        this.j = this.i;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1754Pf
    public final void l() {
        this.j = null;
        this.i = null;
    }
}
