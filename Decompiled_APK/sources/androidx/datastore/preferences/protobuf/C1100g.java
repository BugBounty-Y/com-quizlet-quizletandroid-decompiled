package androidx.datastore.preferences.protobuf;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.mlkit_vision_barcode.U6;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Locale;

/* renamed from: androidx.datastore.preferences.protobuf.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C1100g implements Iterable, Serializable {
    public static final C1100g c = new C1100g(AbstractC1115w.b);
    public static final C1098e d;
    public int a = 0;
    public final byte[] b;

    static {
        d = AbstractC1096c.a() ? new C1098e(1) : new C1098e(0);
    }

    public C1100g(byte[] bArr) {
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

    public static C1100g c(int i, byte[] bArr, int i2) {
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
        return new C1100g(bArrCopyOfRange);
    }

    public byte a(int i) {
        return this.b[i];
    }

    public void e(int i, byte[] bArr) {
        System.arraycopy(this.b, 0, bArr, 0, i);
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C1100g) || size() != ((C1100g) obj).size()) {
            return false;
        }
        if (size() == 0) {
            return true;
        }
        if (!(obj instanceof C1100g)) {
            return obj.equals(this);
        }
        C1100g c1100g = (C1100g) obj;
        int i = this.a;
        int i2 = c1100g.a;
        if (i != 0 && i2 != 0 && i != i2) {
            return false;
        }
        int size = size();
        if (size > c1100g.size()) {
            throw new IllegalArgumentException("Length too large: " + size + size());
        }
        if (size > c1100g.size()) {
            StringBuilder sbV = android.support.v4.media.session.a.v(size, "Ran off end of other: 0, ", ", ");
            sbV.append(c1100g.size());
            throw new IllegalArgumentException(sbV.toString());
        }
        int iG = g() + size;
        int iG2 = g();
        int iG3 = c1100g.g();
        while (iG2 < iG) {
            if (this.b[iG2] != c1100g.b[iG3]) {
                return false;
            }
            iG2++;
            iG3++;
        }
        return true;
    }

    public int g() {
        return 0;
    }

    public byte h(int i) {
        return this.b[i];
    }

    public final int hashCode() {
        int i = this.a;
        if (i != 0) {
            return i;
        }
        int size = size();
        int iG = g();
        int i2 = size;
        for (int i3 = iG; i3 < iG + size; i3++) {
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
            string = U6.b(this);
        } else {
            StringBuilder sb = new StringBuilder();
            int iB = b(0, 47, size());
            sb.append(U6.b(iB == 0 ? c : new C1099f(g(), this.b, iB)));
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
