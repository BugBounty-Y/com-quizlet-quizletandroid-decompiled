package com.google.android.gms.internal.ads;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.ShortBuffer;

/* renamed from: com.google.android.gms.internal.ads.cg, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1926cg implements InterfaceC1688Ef {
    public int b;
    public float c;
    public float d;
    public C2229jf e;
    public C2229jf f;
    public C2229jf g;
    public C2229jf h;
    public boolean i;
    public C1808Yf j;
    public ByteBuffer k;
    public ShortBuffer l;
    public ByteBuffer m;
    public long n;
    public long o;
    public boolean p;

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final void a() {
        if (h()) {
            C2229jf c2229jf = this.e;
            this.g = c2229jf;
            C2229jf c2229jf2 = this.f;
            this.h = c2229jf2;
            if (this.i) {
                int i = c2229jf.a;
                this.j = new C1808Yf(this.c, this.d, i, c2229jf.b, c2229jf2.a);
            } else {
                C1808Yf c1808Yf = this.j;
                if (c1808Yf != null) {
                    c1808Yf.k = 0;
                    c1808Yf.m = 0;
                    c1808Yf.o = 0;
                    c1808Yf.p = 0;
                    c1808Yf.q = 0;
                    c1808Yf.r = 0;
                    c1808Yf.s = 0;
                    c1808Yf.t = 0;
                    c1808Yf.u = 0;
                    c1808Yf.v = 0;
                    c1808Yf.w = 0.0d;
                }
            }
        }
        this.m = InterfaceC1688Ef.a;
        this.n = 0L;
        this.o = 0L;
        this.p = false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final C2229jf b(C2229jf c2229jf) throws zzcm {
        if (c2229jf.c != 2) {
            throw new zzcm("Unhandled input format:", c2229jf);
        }
        int i = this.b;
        if (i == -1) {
            i = c2229jf.a;
        }
        this.e = c2229jf;
        C2229jf c2229jf2 = new C2229jf(i, c2229jf.b, 2);
        this.f = c2229jf2;
        this.i = true;
        return c2229jf2;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final void c(ByteBuffer byteBuffer) {
        if (byteBuffer.hasRemaining()) {
            C1808Yf c1808Yf = this.j;
            c1808Yf.getClass();
            ShortBuffer shortBufferAsShortBuffer = byteBuffer.asShortBuffer();
            int iRemaining = byteBuffer.remaining();
            this.n += iRemaining;
            int iRemaining2 = shortBufferAsShortBuffer.remaining();
            int i = c1808Yf.b;
            int i2 = iRemaining2 / i;
            int i3 = i2 * i;
            short[] sArrF = c1808Yf.f(c1808Yf.j, c1808Yf.k, i2);
            c1808Yf.j = sArrF;
            shortBufferAsShortBuffer.get(sArrF, c1808Yf.k * i, (i3 + i3) / 2);
            c1808Yf.k += i2;
            c1808Yf.e();
            byteBuffer.position(byteBuffer.position() + iRemaining);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final void f() {
        this.c = 1.0f;
        this.d = 1.0f;
        C2229jf c2229jf = C2229jf.e;
        this.e = c2229jf;
        this.f = c2229jf;
        this.g = c2229jf;
        this.h = c2229jf;
        ByteBuffer byteBuffer = InterfaceC1688Ef.a;
        this.k = byteBuffer;
        this.l = byteBuffer.asShortBuffer();
        this.m = byteBuffer;
        this.b = -1;
        this.i = false;
        this.j = null;
        this.n = 0L;
        this.o = 0L;
        this.p = false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final boolean g() {
        if (this.p) {
            C1808Yf c1808Yf = this.j;
            if (c1808Yf != null) {
                AbstractC1795We.L(c1808Yf.m >= 0);
                int i = c1808Yf.m * c1808Yf.b;
                if (i + i != 0) {
                }
            }
            return true;
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final boolean h() {
        if (this.f.a != -1) {
            return Math.abs(this.c + (-1.0f)) >= 1.0E-4f || Math.abs(this.d + (-1.0f)) >= 1.0E-4f || this.f.a != this.e.a;
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final void j() {
        C1808Yf c1808Yf = this.j;
        if (c1808Yf != null) {
            int i = c1808Yf.k;
            int i2 = c1808Yf.r;
            int i3 = c1808Yf.m;
            float f = c1808Yf.c;
            float f2 = c1808Yf.d;
            int i4 = i3 + ((int) (((((((i - i2) / (f / f2)) + i2) + c1808Yf.w) + c1808Yf.o) / (c1808Yf.e * f2)) + 0.5d));
            c1808Yf.w = 0.0d;
            int i5 = c1808Yf.h;
            int i6 = i5 + i5;
            c1808Yf.j = c1808Yf.f(c1808Yf.j, i, i + i6);
            int i7 = 0;
            while (true) {
                int i8 = c1808Yf.b;
                if (i7 >= i6 * i8) {
                    break;
                }
                c1808Yf.j[(i8 * i) + i7] = 0;
                i7++;
            }
            c1808Yf.k += i6;
            c1808Yf.e();
            if (c1808Yf.m > i4) {
                c1808Yf.m = Math.max(i4, 0);
            }
            c1808Yf.k = 0;
            c1808Yf.r = 0;
            c1808Yf.o = 0;
        }
        this.p = true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final ByteBuffer zzb() {
        C1808Yf c1808Yf = this.j;
        if (c1808Yf != null) {
            AbstractC1795We.L(c1808Yf.m >= 0);
            int i = c1808Yf.m;
            int i2 = c1808Yf.b;
            int i3 = i * i2;
            int i4 = i3 + i3;
            if (i4 > 0) {
                if (this.k.capacity() < i4) {
                    ByteBuffer byteBufferOrder = ByteBuffer.allocateDirect(i4).order(ByteOrder.nativeOrder());
                    this.k = byteBufferOrder;
                    this.l = byteBufferOrder.asShortBuffer();
                } else {
                    this.k.clear();
                    this.l.clear();
                }
                ShortBuffer shortBuffer = this.l;
                AbstractC1795We.L(c1808Yf.m >= 0);
                int iMin = Math.min(shortBuffer.remaining() / i2, c1808Yf.m);
                int i5 = iMin * i2;
                shortBuffer.put(c1808Yf.l, 0, i5);
                int i6 = c1808Yf.m - iMin;
                c1808Yf.m = i6;
                short[] sArr = c1808Yf.l;
                System.arraycopy(sArr, i5, sArr, 0, i6 * i2);
                this.o += i4;
                this.k.limit(i4);
                this.m = this.k;
            }
        }
        ByteBuffer byteBuffer = this.m;
        this.m = InterfaceC1688Ef.a;
        return byteBuffer;
    }
}
