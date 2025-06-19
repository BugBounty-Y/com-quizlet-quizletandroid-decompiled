package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.core.view.AbstractC1047f0;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.Serializable;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Locale;

/* loaded from: classes2.dex */
public abstract class BA implements Iterable, Serializable {
    public static final C2905zA b = new C2905zA(WA.b);
    public int a = 0;

    static {
        int i = AbstractC2733vA.a;
    }

    public static BA e(Iterator it2, int i) {
        if (i <= 0) {
            throw new IllegalArgumentException(AbstractC0147y.c(i, "length (", ") must be >= 1"));
        }
        if (i == 1) {
            return (BA) it2.next();
        }
        int i2 = i >>> 1;
        BA baE = e(it2, i2);
        BA baE2 = e(it2, i - i2);
        if (SubsamplingScaleImageView.TILE_SIZE_AUTO - baE.g() < baE2.g()) {
            throw new IllegalArgumentException(androidx.compose.animation.d0.p("ByteString would be too long: ", baE.g(), "+", baE2.g()));
        }
        if (baE2.g() == 0) {
            return baE;
        }
        if (baE.g() == 0) {
            return baE2;
        }
        int iG = baE2.g() + baE.g();
        if (iG < 128) {
            int iG2 = baE.g();
            int iG3 = baE2.g();
            int i3 = iG2 + iG3;
            byte[] bArr = new byte[i3];
            t(0, iG2, baE.g());
            t(0, iG2, i3);
            if (iG2 > 0) {
                baE.h(0, 0, bArr, iG2);
            }
            t(0, iG3, baE2.g());
            t(iG2, i3, i3);
            if (iG3 > 0) {
                baE2.h(0, iG2, bArr, iG3);
            }
            return new C2905zA(bArr);
        }
        if (baE instanceof C2520qB) {
            C2520qB c2520qB = (C2520qB) baE;
            BA ba = c2520qB.e;
            int iG4 = baE2.g() + ba.g();
            BA ba2 = c2520qB.d;
            if (iG4 < 128) {
                int iG5 = ba.g();
                int iG6 = baE2.g();
                int i4 = iG5 + iG6;
                byte[] bArr2 = new byte[i4];
                t(0, iG5, ba.g());
                t(0, iG5, i4);
                if (iG5 > 0) {
                    ba.h(0, 0, bArr2, iG5);
                }
                t(0, iG6, baE2.g());
                t(iG5, i4, i4);
                if (iG6 > 0) {
                    baE2.h(0, iG5, bArr2, iG6);
                }
                return new C2520qB(ba2, new C2905zA(bArr2));
            }
            if (ba2.j() > ba.j() && c2520qB.g > baE2.j()) {
                return new C2520qB(ba2, new C2520qB(ba, baE2));
            }
        }
        if (iG >= C2520qB.z(Math.max(baE.j(), baE2.j()) + 1)) {
            return new C2520qB(baE, baE2);
        }
        Sq sq = new Sq();
        sq.a = new ArrayDeque();
        sq.d(baE);
        sq.d(baE2);
        ArrayDeque arrayDeque = (ArrayDeque) sq.a;
        BA c2520qB2 = (BA) arrayDeque.pop();
        while (!arrayDeque.isEmpty()) {
            c2520qB2 = new C2520qB((BA) arrayDeque.pop(), c2520qB2);
        }
        return c2520qB2;
    }

    public static int t(int i, int i2, int i3) {
        int i4 = i2 - i;
        if ((i | i2 | i4 | (i3 - i2)) >= 0) {
            return i4;
        }
        if (i < 0) {
            throw new IndexOutOfBoundsException(AbstractC0147y.c(i, "Beginning index: ", " < 0"));
        }
        if (i2 < i) {
            throw new IndexOutOfBoundsException(androidx.compose.animation.d0.p("Beginning index larger than ending index: ", i, ", ", i2));
        }
        throw new IndexOutOfBoundsException(androidx.compose.animation.d0.p("End index: ", i2, " >= ", i3));
    }

    public static BA v(ArrayList arrayList) {
        int size;
        if (arrayList == null) {
            Iterator it2 = arrayList.iterator();
            size = 0;
            while (it2.hasNext()) {
                it2.next();
                size++;
            }
        } else {
            size = arrayList.size();
        }
        return size == 0 ? b : e(arrayList.iterator(), size);
    }

    public static C2905zA w(int i, byte[] bArr, int i2) {
        t(i, i + i2, bArr.length);
        byte[] bArr2 = new byte[i2];
        System.arraycopy(bArr, i, bArr2, 0, i2);
        return new C2905zA(bArr2);
    }

    public static void x(int i, int i2) {
        if (((i2 - (i + 1)) | i) < 0) {
            if (i >= 0) {
                throw new ArrayIndexOutOfBoundsException(androidx.compose.animation.d0.p("Index > length: ", i, ", ", i2));
            }
            throw new ArrayIndexOutOfBoundsException(android.support.v4.media.session.a.f(i, "Index < 0: "));
        }
    }

    public final byte[] a() {
        int iG = g();
        if (iG == 0) {
            return WA.b;
        }
        byte[] bArr = new byte[iG];
        h(0, 0, bArr, iG);
        return bArr;
    }

    public abstract byte b(int i);

    public abstract byte c(int i);

    public abstract boolean equals(Object obj);

    public abstract int g();

    public abstract void h(int i, int i2, byte[] bArr, int i3);

    public final int hashCode() {
        int iM = this.a;
        if (iM == 0) {
            int iG = g();
            iM = m(iG, 0, iG);
            if (iM == 0) {
                iM = 1;
            }
            this.a = iM;
        }
        return iM;
    }

    public abstract int j();

    public abstract boolean k();

    public abstract int m(int i, int i2, int i3);

    public abstract BA n(int i, int i2);

    public abstract AbstractC1047f0 o();

    public abstract void s(HA ha);

    public final String toString() {
        Locale locale = Locale.ROOT;
        String hexString = Integer.toHexString(System.identityHashCode(this));
        int iG = g();
        String strE = g() <= 50 ? AbstractC2543qs.e(this) : AbstractC2543qs.e(n(0, 47)).concat("...");
        StringBuilder sb = new StringBuilder("<ByteString@");
        sb.append(hexString);
        sb.append(" size=");
        sb.append(iG);
        sb.append(" contents=\"");
        return android.support.v4.media.session.a.t(sb, strE, "\">");
    }

    @Override // java.lang.Iterable
    /* renamed from: u, reason: merged with bridge method [inline-methods] */
    public Pu iterator() {
        return new C2819xA(this);
    }
}
