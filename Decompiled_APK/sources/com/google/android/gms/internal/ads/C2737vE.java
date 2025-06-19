package com.google.android.gms.internal.ads;

import com.skydoves.balloon.internals.DefinitionKt;
import java.nio.ByteBuffer;

/* renamed from: com.google.android.gms.internal.ads.vE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2737vE extends AbstractC1754Pf {
    public static final int i = Float.floatToIntBits(Float.NaN);

    public static void m(int i2, ByteBuffer byteBuffer) {
        int iFloatToIntBits = Float.floatToIntBits((float) (i2 * 4.656612875245797E-10d));
        if (iFloatToIntBits == i) {
            iFloatToIntBits = Float.floatToIntBits(DefinitionKt.NO_Float_VALUE);
        }
        byteBuffer.putInt(iFloatToIntBits);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final void c(ByteBuffer byteBuffer) {
        ByteBuffer byteBufferE;
        int iPosition = byteBuffer.position();
        int iLimit = byteBuffer.limit();
        int i2 = iLimit - iPosition;
        int i3 = this.b.c;
        if (i3 == 21) {
            byteBufferE = e((i2 / 3) * 4);
            while (iPosition < iLimit) {
                m(((byteBuffer.get(iPosition) & 255) << 8) | ((byteBuffer.get(iPosition + 1) & 255) << 16) | ((byteBuffer.get(iPosition + 2) & 255) << 24), byteBufferE);
                iPosition += 3;
            }
        } else if (i3 == 22) {
            byteBufferE = e(i2);
            while (iPosition < iLimit) {
                int i4 = byteBuffer.get(iPosition) & 255;
                int i5 = (byteBuffer.get(iPosition + 1) & 255) << 8;
                m(i4 | i5 | ((byteBuffer.get(iPosition + 2) & 255) << 16) | ((byteBuffer.get(iPosition + 3) & 255) << 24), byteBufferE);
                iPosition += 4;
            }
        } else if (i3 == 1342177280) {
            byteBufferE = e((i2 / 3) * 4);
            while (iPosition < iLimit) {
                m(((byteBuffer.get(iPosition + 2) & 255) << 8) | ((byteBuffer.get(iPosition + 1) & 255) << 16) | ((byteBuffer.get(iPosition) & 255) << 24), byteBufferE);
                iPosition += 3;
            }
        } else {
            if (i3 != 1610612736) {
                throw new IllegalStateException();
            }
            byteBufferE = e(i2);
            while (iPosition < iLimit) {
                int i6 = byteBuffer.get(iPosition + 3) & 255;
                int i7 = (byteBuffer.get(iPosition + 2) & 255) << 8;
                m(i6 | i7 | ((byteBuffer.get(iPosition + 1) & 255) << 16) | ((byteBuffer.get(iPosition) & 255) << 24), byteBufferE);
                iPosition += 4;
            }
        }
        byteBuffer.position(byteBuffer.limit());
        byteBufferE.flip();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1754Pf
    public final C2229jf d(C2229jf c2229jf) throws zzcm {
        String str = Yo.a;
        int i2 = c2229jf.c;
        if (i2 == 21 || i2 == 1342177280 || i2 == 22 || i2 == 1610612736) {
            return new C2229jf(c2229jf.a, c2229jf.b, 4);
        }
        if (i2 == 4) {
            return C2229jf.e;
        }
        throw new zzcm("Unhandled input format:", c2229jf);
    }
}
