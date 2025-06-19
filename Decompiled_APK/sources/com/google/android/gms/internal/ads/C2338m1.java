package com.google.android.gms.internal.ads;

import java.io.EOFException;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.m1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2338m1 implements InterfaceC2724v1, InterfaceC2589rw {
    public static final long[] d = {128, 64, 32, 16, 8, 4, 2, 1};
    public static final byte[] e = {79, 103, 103, 83, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, -43, -59, -9, 1, 19, 79, 112, 117, 115, 72, 101, 97, 100, 1, 2, 56, 1, Byte.MIN_VALUE, -69, 0, 0, 0, 0, 0};
    public static final byte[] f = {79, 103, 103, 83, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 11, -103, 87, 83, 1, 16, 79, 112, 117, 115, 84, 97, 103, 115, 0, 0, 0, 0, 0, 0, 0, 0};
    public int a;
    public int b;
    public Object c;

    public C2338m1(int i) {
        switch (i) {
            case 5:
                this.c = new Fp(7);
                this.a = 8000;
                this.b = 8000;
                break;
            default:
                this.c = new byte[8];
                break;
        }
    }

    public static long d(int i, boolean z, byte[] bArr) {
        long j = bArr[0] & 255;
        if (z) {
            j &= ~d[i - 1];
        }
        for (int i2 = 1; i2 < i; i2++) {
            j = (j << 8) | (bArr[i2] & 255);
        }
        return j;
    }

    public static final void e(ByteBuffer byteBuffer, long j, int i, int i2, boolean z) {
        byteBuffer.put((byte) 79);
        byteBuffer.put((byte) 103);
        byteBuffer.put((byte) 103);
        byteBuffer.put((byte) 83);
        byteBuffer.put((byte) 0);
        byteBuffer.put(true != z ? (byte) 0 : (byte) 2);
        byteBuffer.putLong(j);
        byteBuffer.putInt(0);
        byteBuffer.putInt(i);
        byteBuffer.putInt(0);
        byteBuffer.put(AbstractC2025es.d(i2));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2724v1
    public int a() {
        int i = this.a;
        return i == -1 ? ((Kn) this.c).C() : i;
    }

    /* JADX WARN: Code restructure failed: missing block: B:61:0x00f6, code lost:
    
        if (r2.size() < r12) goto L98;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.String b(java.util.ArrayList r18, java.util.ArrayList r19) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 332
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2338m1.b(java.util.ArrayList, java.util.ArrayList):java.lang.String");
    }

    public void c(MC mc, List list) {
        int length;
        ByteBuffer byteBuffer;
        ByteBuffer byteBuffer2 = mc.e;
        byteBuffer2.getClass();
        if (byteBuffer2.limit() - mc.e.position() == 0) {
            return;
        }
        byte[] bArr = null;
        if (this.a == 2 && (list.size() == 1 || list.size() == 3)) {
            bArr = (byte[]) list.get(0);
        }
        ByteBuffer byteBuffer3 = mc.e;
        int iPosition = byteBuffer3.position();
        int iLimit = byteBuffer3.limit();
        int i = iLimit - iPosition;
        int i2 = (i + 255) / 255;
        int i3 = i2 + 27 + i;
        if (this.a == 2) {
            length = bArr != null ? bArr.length + 28 : 47;
            i3 += length + 44;
        } else {
            length = 0;
        }
        if (((ByteBuffer) this.c).capacity() < i3) {
            this.c = ByteBuffer.allocate(i3).order(ByteOrder.LITTLE_ENDIAN);
        } else {
            ((ByteBuffer) this.c).clear();
        }
        ByteBuffer byteBuffer4 = (ByteBuffer) this.c;
        if (this.a == 2) {
            if (bArr != null) {
                byteBuffer = byteBuffer4;
                e(byteBuffer, 0L, 0, 1, true);
                int length2 = bArr.length;
                byteBuffer.put(AbstractC2025es.d(length2));
                byteBuffer.put(bArr);
                int i4 = length2 + 28;
                byteBuffer.putInt(22, Yo.l(byteBuffer.arrayOffset(), i4, byteBuffer.array(), 0));
                byteBuffer.position(i4);
            } else {
                byteBuffer = byteBuffer4;
                byteBuffer.put(e);
            }
            byteBuffer.put(f);
        } else {
            byteBuffer = byteBuffer4;
        }
        int iC = this.b + ((int) ((LA.C(byteBuffer3.get(0), byteBuffer3.limit() > 1 ? byteBuffer3.get(1) : (byte) 0) * 48000) / 1000000));
        this.b = iC;
        ByteBuffer byteBuffer5 = byteBuffer;
        e(byteBuffer5, iC, this.a, i2, false);
        for (int i5 = 0; i5 < i2; i5++) {
            if (i >= 255) {
                byteBuffer5.put((byte) -1);
                i -= 255;
            } else {
                byteBuffer5.put((byte) i);
                i = 0;
            }
        }
        while (iPosition < iLimit) {
            byteBuffer5.put(byteBuffer3.get(iPosition));
            iPosition++;
        }
        byteBuffer3.position(byteBuffer3.limit());
        byteBuffer5.flip();
        if (this.a == 2) {
            byteBuffer5.putInt(length + 66, Yo.l(byteBuffer5.arrayOffset() + length + 44, byteBuffer5.limit() - byteBuffer5.position(), byteBuffer5.array(), 0));
        } else {
            byteBuffer5.putInt(22, Yo.l(byteBuffer5.arrayOffset(), byteBuffer5.limit() - byteBuffer5.position(), byteBuffer5.array(), 0));
        }
        this.a++;
        this.c = byteBuffer5;
        mc.v();
        mc.w(((ByteBuffer) this.c).remaining());
        mc.e.put((ByteBuffer) this.c);
        mc.x();
    }

    public long f(P p, boolean z, boolean z2, int i) throws EOFException, InterruptedIOException {
        int i2;
        int i3 = this.a;
        byte[] bArr = (byte[]) this.c;
        if (i3 == 0) {
            if (!p.h(bArr, 0, 1, z)) {
                return -1L;
            }
            int i4 = bArr[0] & 255;
            int i5 = 0;
            while (true) {
                if (i5 >= 8) {
                    i2 = -1;
                    break;
                }
                i2 = i5 + 1;
                if ((d[i5] & i4) != 0) {
                    break;
                }
                i5 = i2;
            }
            this.b = i2;
            if (i2 == -1) {
                throw new IllegalStateException("No valid varint length mask found");
            }
            this.a = 1;
        }
        int i6 = this.b;
        if (i6 > i) {
            this.a = 0;
            return -2L;
        }
        if (i6 != 1) {
            p.h(bArr, 1, i6 - 1, false);
        }
        this.a = 0;
        return d(this.b, z2, bArr);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2724v1
    public int zza() {
        return this.a;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2724v1
    public int zzb() {
        return this.b;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2589rw
    /* renamed from: zza, reason: collision with other method in class */
    public Fw mo22zza() {
        return new C2807wz(null, this.a, this.b, false, (Fp) this.c);
    }
}
