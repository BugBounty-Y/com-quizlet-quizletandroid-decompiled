package androidx.glance.appwidget.protobuf;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import androidx.datastore.preferences.protobuf.C1097d;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Locale;

/* renamed from: androidx.glance.appwidget.protobuf.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C1194f implements Iterable, Serializable {
    public static final C1194f c = new C1194f(AbstractC1209v.b);
    public static final C1192d d;
    public int a = 0;
    public final byte[] b;

    static {
        d = AbstractC1191c.a() ? new C1192d(1) : new C1192d(0);
    }

    public C1194f(byte[] bArr) {
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
            throw new IndexOutOfBoundsException(d0.p("Beginning index larger than ending index: ", i, ", ", i2));
        }
        throw new IndexOutOfBoundsException(d0.p("End index: ", i2, " >= ", i3));
    }

    public static C1194f c(int i, byte[] bArr, int i2) {
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
        return new C1194f(bArrCopyOfRange);
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
        if (!(obj instanceof C1194f) || size() != ((C1194f) obj).size()) {
            return false;
        }
        if (size() == 0) {
            return true;
        }
        if (!(obj instanceof C1194f)) {
            return obj.equals(this);
        }
        C1194f c1194f = (C1194f) obj;
        int i = this.a;
        int i2 = c1194f.a;
        if (i != 0 && i2 != 0 && i != i2) {
            return false;
        }
        int size = size();
        if (size > c1194f.size()) {
            throw new IllegalArgumentException("Length too large: " + size + size());
        }
        if (size > c1194f.size()) {
            StringBuilder sbV = android.support.v4.media.session.a.v(size, "Ran off end of other: 0, ", ", ");
            sbV.append(c1194f.size());
            throw new IllegalArgumentException(sbV.toString());
        }
        int iE = e() + size;
        int iE2 = e();
        int iE3 = c1194f.e();
        while (iE2 < iE) {
            if (this.b[iE2] != c1194f.b[iE3]) {
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
            string = B7.a(this);
        } else {
            StringBuilder sb = new StringBuilder();
            int iB = b(0, 47, size());
            sb.append(B7.a(iB == 0 ? c : new C1193e(e(), this.b, iB)));
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
