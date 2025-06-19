package com.google.android.gms.internal.ads;

import androidx.core.view.AbstractC1047f0;
import com.comscore.streaming.AdvertisementType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.NoSuchElementException;

/* renamed from: com.google.android.gms.internal.ads.qB, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2520qB extends BA {
    public static final int[] h = {1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, AdvertisementType.BRANDED_ON_DEMAND_POST_ROLL, 377, 610, 987, 1597, 2584, 4181, 6765, 10946, 17711, 28657, 46368, 75025, 121393, 196418, 317811, 514229, 832040, 1346269, 2178309, 3524578, 5702887, 9227465, 14930352, 24157817, 39088169, 63245986, 102334155, 165580141, 267914296, 433494437, 701408733, 1134903170, 1836311903, SubsamplingScaleImageView.TILE_SIZE_AUTO};
    public final int c;
    public final BA d;
    public final BA e;
    public final int f;
    public final int g;

    public C2520qB(BA ba, BA ba2) {
        this.d = ba;
        this.e = ba2;
        int iG = ba.g();
        this.f = iG;
        this.c = ba2.g() + iG;
        this.g = Math.max(ba.j(), ba2.j()) + 1;
    }

    public static int z(int i) {
        return i >= 47 ? SubsamplingScaleImageView.TILE_SIZE_AUTO : h[i];
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final byte b(int i) {
        BA.x(i, this.c);
        return c(i);
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final byte c(int i) {
        int i2 = this.f;
        return i < i2 ? this.d.c(i) : this.e.c(i - i2);
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof BA) {
            BA ba = (BA) obj;
            int iG = ba.g();
            int i = this.c;
            if (i == iG) {
                if (i == 0) {
                    return true;
                }
                int i2 = this.a;
                int i3 = ba.a;
                if (i2 == 0 || i3 == 0 || i2 == i3) {
                    C2477pB c2477pB = new C2477pB(this);
                    C2905zA c2905zAA = c2477pB.next();
                    C2477pB c2477pB2 = new C2477pB(ba);
                    C2905zA c2905zAA2 = c2477pB2.next();
                    int i4 = 0;
                    int i5 = 0;
                    int i6 = 0;
                    while (true) {
                        int iG2 = c2905zAA.g() - i4;
                        int iG3 = c2905zAA2.g() - i5;
                        int iMin = Math.min(iG2, iG3);
                        if (!(i4 == 0 ? c2905zAA.A(c2905zAA2, i5, iMin) : c2905zAA2.A(c2905zAA, i4, iMin))) {
                            break;
                        }
                        i6 += iMin;
                        if (i6 >= i) {
                            if (i6 == i) {
                                return true;
                            }
                            throw new IllegalStateException();
                        }
                        if (iMin == iG2) {
                            c2905zAA = c2477pB.next();
                            i4 = 0;
                        } else {
                            i4 += iMin;
                        }
                        if (iMin == iG3) {
                            c2905zAA2 = c2477pB2.next();
                            i5 = 0;
                        } else {
                            i5 += iMin;
                        }
                    }
                }
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final int g() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final void h(int i, int i2, byte[] bArr, int i3) {
        int i4 = i + i3;
        BA ba = this.d;
        int i5 = this.f;
        if (i4 <= i5) {
            ba.h(i, i2, bArr, i3);
            return;
        }
        BA ba2 = this.e;
        if (i >= i5) {
            ba2.h(i - i5, i2, bArr, i3);
            return;
        }
        int i6 = i5 - i;
        ba.h(i, i2, bArr, i6);
        ba2.h(0, i2 + i6, bArr, i3 - i6);
    }

    @Override // com.google.android.gms.internal.ads.BA, java.lang.Iterable
    public final /* synthetic */ Iterator iterator() {
        return new C2434oB(this);
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final int j() {
        return this.g;
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final boolean k() {
        return this.c >= z(this.g);
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final int m(int i, int i2, int i3) {
        int i4 = i2 + i3;
        BA ba = this.d;
        int i5 = this.f;
        if (i4 <= i5) {
            return ba.m(i, i2, i3);
        }
        BA ba2 = this.e;
        if (i2 >= i5) {
            return ba2.m(i, i2 - i5, i3);
        }
        int i6 = i5 - i2;
        return ba2.m(ba.m(i, i2, i6), 0, i3 - i6);
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final BA n(int i, int i2) {
        int i3 = this.c;
        int iT = BA.t(i, i2, i3);
        if (iT == 0) {
            return BA.b;
        }
        if (iT == i3) {
            return this;
        }
        BA ba = this.d;
        int i4 = this.f;
        if (i2 <= i4) {
            return ba.n(i, i2);
        }
        int i5 = i2 - i4;
        BA ba2 = this.e;
        return i >= i4 ? ba2.n(i - i4, i5) : new C2520qB(ba.n(i, ba.g()), ba2.n(0, i5));
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final AbstractC1047f0 o() {
        C2905zA c2905zA;
        ArrayList arrayList = new ArrayList();
        ArrayDeque arrayDeque = new ArrayDeque(this.g);
        arrayDeque.push(this);
        BA ba = this.d;
        while (ba instanceof C2520qB) {
            C2520qB c2520qB = (C2520qB) ba;
            arrayDeque.push(c2520qB);
            ba = c2520qB.d;
        }
        C2905zA c2905zA2 = (C2905zA) ba;
        while (true) {
            if (!(c2905zA2 != null)) {
                Iterator it2 = arrayList.iterator();
                int i = 0;
                int iRemaining = 0;
                while (it2.hasNext()) {
                    ByteBuffer byteBuffer = (ByteBuffer) it2.next();
                    iRemaining += byteBuffer.remaining();
                    i = byteBuffer.hasArray() ? i | 1 : byteBuffer.isDirect() ? i | 2 : i | 4;
                }
                if (i == 2) {
                    return new DA(iRemaining, arrayList);
                }
                XA xa = new XA();
                xa.a = arrayList.iterator();
                xa.c = 0;
                Iterator it3 = arrayList.iterator();
                while (it3.hasNext()) {
                    xa.c++;
                }
                xa.d = -1;
                if (!xa.d()) {
                    xa.b = WA.c;
                    xa.d = 0;
                    xa.e = 0;
                    xa.i = 0L;
                }
                return new EA(xa);
            }
            if (c2905zA2 == null) {
                throw new NoSuchElementException();
            }
            while (true) {
                if (arrayDeque.isEmpty()) {
                    c2905zA = null;
                    break;
                }
                BA ba2 = ((C2520qB) arrayDeque.pop()).e;
                while (ba2 instanceof C2520qB) {
                    C2520qB c2520qB2 = (C2520qB) ba2;
                    arrayDeque.push(c2520qB2);
                    ba2 = c2520qB2.d;
                }
                c2905zA = (C2905zA) ba2;
                if (c2905zA.g() != 0) {
                    break;
                }
            }
            arrayList.add(ByteBuffer.wrap(c2905zA2.c, c2905zA2.z(), c2905zA2.g()).asReadOnlyBuffer());
            c2905zA2 = c2905zA;
        }
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final void s(HA ha) {
        this.d.s(ha);
        this.e.s(ha);
    }

    @Override // com.google.android.gms.internal.ads.BA
    /* renamed from: u */
    public final Pu iterator() {
        return new C2434oB(this);
    }
}
