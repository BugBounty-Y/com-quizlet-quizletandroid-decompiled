package com.google.protobuf;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.datastore.preferences.protobuf.C1097d;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Locale;

/* renamed from: com.google.protobuf.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class C4012f implements Iterable, Serializable {
    public static final C4012f c = new C4012f(C.b);
    public static final C4010d d;
    public int a = 0;
    public final byte[] b;

    static {
        d = AbstractC4008c.a() ? new C4010d(1) : new C4010d(0);
    }

    public C4012f(byte[] bArr) {
        bArr.getClass();
        this.b = bArr;
    }

    public static int b(int i, int i2, int i3) {
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

    public static C4012f c(int i, byte[] bArr, int i2) {
        byte[] bArrCopyOfRange;
        b(i, i + i2, bArr.length);
        switch (d.a) {
            case 0:
                bArrCopyOfRange = Arrays.copyOfRange(bArr, i, i2 + i);
                break;
            default:
                bArrCopyOfRange = new byte[i2];
                System.arraycopy(bArr, i, bArrCopyOfRange, 0, i2);
                break;
        }
        return new C4012f(bArrCopyOfRange);
    }

    public byte a(int i) {
        return this.b[i];
    }

    public int e() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C4012f) || size() != ((C4012f) obj).size()) {
            return false;
        }
        if (size() == 0) {
            return true;
        }
        if (!(obj instanceof C4012f)) {
            return obj.equals(this);
        }
        C4012f c4012f = (C4012f) obj;
        int i = this.a;
        int i2 = c4012f.a;
        if (i != 0 && i2 != 0 && i != i2) {
            return false;
        }
        int size = size();
        if (size > c4012f.size()) {
            throw new IllegalArgumentException("Length too large: " + size + size());
        }
        if (size > c4012f.size()) {
            StringBuilder sbV = android.support.v4.media.session.a.v(size, "Ran off end of other: 0, ", ", ");
            sbV.append(c4012f.size());
            throw new IllegalArgumentException(sbV.toString());
        }
        int iE = e() + size;
        int iE2 = e();
        int iE3 = c4012f.e();
        while (iE2 < iE) {
            if (this.b[iE2] != c4012f.b[iE3]) {
                return false;
            }
            iE2++;
            iE3++;
        }
        return true;
    }

    public byte g(int i) {
        return this.b[i];
    }

    public final int hashCode() {
        int i = this.a;
        if (i != 0) {
            return i;
        }
        int size = size();
        int iE = e();
        int i2 = size;
        for (int i3 = iE; i3 < iE + size; i3++) {
            i2 = (i2 * 31) + this.b[i3];
        }
        if (i2 == 0) {
            i2 = 1;
        }
        this.a = i2;
        return i2;
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        return new C1097d(this);
    }

    public int size() {
        return this.b.length;
    }

    public final String toString() {
        String string;
        Locale locale = Locale.ROOT;
        String hexString = Integer.toHexString(System.identityHashCode(this));
        int size = size();
        if (size() <= 50) {
            string = h0.c(this);
        } else {
            StringBuilder sb = new StringBuilder();
            int iB = b(0, 47, size());
            sb.append(h0.c(iB == 0 ? c : new C4011e(e(), this.b, iB)));
            sb.append("...");
            string = sb.toString();
        }
        StringBuilder sb2 = new StringBuilder("<ByteString@");
        sb2.append(hexString);
        sb2.append(" size=");
        sb2.append(size);
        sb2.append(" contents=\"");
        return android.support.v4.media.session.a.t(sb2, string, "\">");
    }
}
