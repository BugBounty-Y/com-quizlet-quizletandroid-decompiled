package com.google.android.gms.internal.fido;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.datastore.preferences.protobuf.C1097d;
import java.io.ByteArrayInputStream;
import java.io.Serializable;
import java.util.Iterator;
import java.util.Locale;

/* loaded from: classes2.dex */
public class T implements Iterable, Serializable {
    public static final T c = new T(U.a);
    public int a = 0;
    public final byte[] b;

    static {
        int i = Q.a;
    }

    public T(byte[] bArr) {
        bArr.getClass();
        this.b = bArr;
    }

    public static int j(int i, int i2, int i3) {
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

    public static T k(int i, byte[] bArr) {
        j(0, i, bArr.length);
        byte[] bArr2 = new byte[i];
        System.arraycopy(bArr, 0, bArr2, 0, i);
        return new T(bArr2);
    }

    public byte a(int i) {
        return this.b[i];
    }

    public byte b(int i) {
        return this.b[i];
    }

    public int c() {
        return 0;
    }

    public int e() {
        return this.b.length;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof T) || e() != ((T) obj).e()) {
            return false;
        }
        if (e() == 0) {
            return true;
        }
        if (!(obj instanceof T)) {
            return obj.equals(this);
        }
        T t = (T) obj;
        int i = this.a;
        int i2 = t.a;
        if (i != 0 && i2 != 0 && i != i2) {
            return false;
        }
        int iE = e();
        if (iE > t.e()) {
            throw new IllegalArgumentException("Length too large: " + iE + e());
        }
        if (iE > t.e()) {
            throw new IllegalArgumentException(androidx.compose.animation.d0.p("Ran off end of other: 0, ", iE, ", ", t.e()));
        }
        int iC = c() + iE;
        int iC2 = c();
        int iC3 = t.c();
        while (iC2 < iC) {
            if (this.b[iC2] != t.b[iC3]) {
                return false;
            }
            iC2++;
            iC3++;
        }
        return true;
    }

    public void g(int i, byte[] bArr) {
        System.arraycopy(this.b, 0, bArr, 0, i);
    }

    public final ByteArrayInputStream h() {
        return new ByteArrayInputStream(this.b, c(), e());
    }

    public final int hashCode() {
        int i = this.a;
        if (i != 0) {
            return i;
        }
        int iE = e();
        int iC = c();
        byte[] bArr = U.a;
        int i2 = iE;
        for (int i3 = iC; i3 < iC + iE; i3++) {
            i2 = (i2 * 31) + this.b[i3];
        }
        int i4 = i2 != 0 ? i2 : 1;
        this.a = i4;
        return i4;
    }

    @Override // java.lang.Iterable
    public final /* synthetic */ Iterator iterator() {
        return new C1097d(this);
    }

    public final byte[] m() {
        int iE = e();
        if (iE == 0) {
            return U.a;
        }
        byte[] bArr = new byte[iE];
        g(iE, bArr);
        return bArr;
    }

    public final String toString() {
        String strConcat;
        Locale locale = Locale.ROOT;
        String hexString = Integer.toHexString(System.identityHashCode(this));
        int iE = e();
        if (e() <= 50) {
            strConcat = AbstractC2937a.c(this);
        } else {
            int iJ = j(0, 47, e());
            strConcat = AbstractC2937a.c(iJ == 0 ? c : new S(c(), this.b, iJ)).concat("...");
        }
        StringBuilder sb = new StringBuilder("<ByteString@");
        sb.append(hexString);
        sb.append(" size=");
        sb.append(iE);
        sb.append(" contents=\"");
        return android.support.v4.media.session.a.t(sb, strConcat, "\">");
    }
}
