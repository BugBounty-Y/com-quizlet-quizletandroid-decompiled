package com.google.android.gms.internal.measurement;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.datastore.preferences.protobuf.C1097d;
import java.io.Serializable;
import java.util.Iterator;
import java.util.Locale;

/* loaded from: classes2.dex */
public class O1 implements Iterable, Serializable {
    public static final O1 c = new O1(AbstractC2980d2.b);
    public int a = 0;
    public final byte[] b;

    static {
        int i = L1.a;
    }

    public O1(byte[] bArr) {
        bArr.getClass();
        this.b = bArr;
    }

    public static int e(int i, int i2, int i3) {
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

    public static O1 g(int i, byte[] bArr, int i2) {
        e(i, i + i2, bArr.length);
        byte[] bArr2 = new byte[i2];
        System.arraycopy(bArr, i, bArr2, 0, i2);
        return new O1(bArr2);
    }

    public byte a(int i) {
        return this.b[i];
    }

    public byte b(int i) {
        return this.b[i];
    }

    public int c() {
        return this.b.length;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if ((obj instanceof O1) && c() == ((O1) obj).c()) {
            if (c() == 0) {
                return true;
            }
            if (!(obj instanceof O1)) {
                return obj.equals(this);
            }
            O1 o1 = (O1) obj;
            int i = this.a;
            int i2 = o1.a;
            if (i == 0 || i2 == 0 || i == i2) {
                int iC = c();
                if (iC > o1.c()) {
                    throw new IllegalArgumentException("Length too large: " + iC + c());
                }
                if (iC > o1.c()) {
                    throw new IllegalArgumentException(androidx.compose.animation.d0.p("Ran off end of other: 0, ", iC, ", ", o1.c()));
                }
                int i3 = 0;
                int i4 = 0;
                while (i3 < iC) {
                    if (this.b[i3] == o1.b[i4]) {
                        i3++;
                        i4++;
                    }
                }
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        int i = this.a;
        if (i != 0) {
            return i;
        }
        int iC = c();
        int i2 = iC;
        for (int i3 = 0; i3 < iC; i3++) {
            i2 = (i2 * 31) + this.b[i3];
        }
        if (i2 == 0) {
            i2 = 1;
        }
        this.a = i2;
        return i2;
    }

    @Override // java.lang.Iterable
    public final /* synthetic */ Iterator iterator() {
        return new C1097d(this);
    }

    public final String toString() {
        String strConcat;
        Locale locale = Locale.ROOT;
        String hexString = Integer.toHexString(System.identityHashCode(this));
        int iC = c();
        if (c() <= 50) {
            strConcat = com.google.android.gms.internal.mlkit_vision_common.B3.a(this);
        } else {
            int iE = e(0, 47, c());
            strConcat = com.google.android.gms.internal.mlkit_vision_common.B3.a(iE == 0 ? c : new M1(iE, this.b)).concat("...");
        }
        StringBuilder sb = new StringBuilder("<ByteString@");
        sb.append(hexString);
        sb.append(" size=");
        sb.append(iC);
        sb.append(" contents=\"");
        return android.support.v4.media.session.a.t(sb, strConcat, "\">");
    }
}
