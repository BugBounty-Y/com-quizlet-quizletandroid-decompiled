package androidx.compose.ui.text.input;

import androidx.compose.animation.d0;
import androidx.compose.ui.text.C0995g;
import com.google.android.gms.internal.ads.InterfaceC2724v1;
import com.google.android.gms.internal.ads.Kn;
import com.google.android.gms.internal.ads.Mp;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.B5;
import java.util.NoSuchElementException;

/* renamed from: androidx.compose.ui.text.input.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1007j implements InterfaceC2724v1 {
    public final /* synthetic */ int a = 3;
    public int b;
    public int c;
    public int d;
    public int e;
    public Object f;

    public /* synthetic */ C1007j() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2724v1
    public int a() {
        Kn kn = (Kn) this.f;
        int i = this.c;
        if (i == 8) {
            return kn.z();
        }
        if (i == 16) {
            return kn.D();
        }
        int i2 = this.d;
        this.d = i2 + 1;
        if (i2 % 2 != 0) {
            return this.e & 15;
        }
        int iZ = kn.z();
        this.e = iZ;
        return (iZ & 240) >> 4;
    }

    public void b(int i, int i2) {
        long jC = AbstractC3205m5.c(i, i2);
        ((androidx.compose.ui.text.android.selection.f) this.f).m(i, i2, "");
        long jF = B5.f(AbstractC3205m5.c(this.b, this.c), jC);
        i(androidx.compose.ui.text.K.e(jF));
        h(androidx.compose.ui.text.K.d(jF));
        int i3 = this.d;
        if (i3 != -1) {
            long jF2 = B5.f(AbstractC3205m5.c(i3, this.e), jC);
            if (androidx.compose.ui.text.K.b(jF2)) {
                this.d = -1;
                this.e = -1;
            } else {
                this.d = androidx.compose.ui.text.K.e(jF2);
                this.e = androidx.compose.ui.text.K.d(jF2);
            }
        }
    }

    public char c(int i) {
        androidx.compose.ui.text.android.selection.f fVar = (androidx.compose.ui.text.android.selection.f) this.f;
        androidx.compose.runtime.changelist.K k = (androidx.compose.runtime.changelist.K) fVar.e;
        if (k != null && i >= fVar.b) {
            int iC = k.b - k.c();
            int i2 = fVar.b;
            if (i >= iC + i2) {
                return ((String) fVar.d).charAt(i - ((iC - fVar.c) + i2));
            }
            int i3 = i - i2;
            int i4 = k.c;
            return i3 < i4 ? ((char[]) k.e)[i3] : ((char[]) k.e)[(i3 - i4) + k.d];
        }
        return ((String) fVar.d).charAt(i);
    }

    public androidx.compose.ui.text.K d() {
        int i = this.d;
        if (i != -1) {
            return new androidx.compose.ui.text.K(AbstractC3205m5.c(i, this.e));
        }
        return null;
    }

    public void e(int i, int i2, String str) {
        androidx.compose.ui.text.android.selection.f fVar = (androidx.compose.ui.text.android.selection.f) this.f;
        if (i < 0 || i > fVar.d()) {
            StringBuilder sbV = android.support.v4.media.session.a.v(i, "start (", ") offset is outside of text region ");
            sbV.append(fVar.d());
            throw new IndexOutOfBoundsException(sbV.toString());
        }
        if (i2 < 0 || i2 > fVar.d()) {
            StringBuilder sbV2 = android.support.v4.media.session.a.v(i2, "end (", ") offset is outside of text region ");
            sbV2.append(fVar.d());
            throw new IndexOutOfBoundsException(sbV2.toString());
        }
        if (i > i2) {
            throw new IllegalArgumentException(d0.p("Do not set reversed range: ", i, " > ", i2));
        }
        fVar.m(i, i2, str);
        i(str.length() + i);
        h(str.length() + i);
        this.d = -1;
        this.e = -1;
    }

    public void f(int i, int i2) {
        androidx.compose.ui.text.android.selection.f fVar = (androidx.compose.ui.text.android.selection.f) this.f;
        if (i < 0 || i > fVar.d()) {
            StringBuilder sbV = android.support.v4.media.session.a.v(i, "start (", ") offset is outside of text region ");
            sbV.append(fVar.d());
            throw new IndexOutOfBoundsException(sbV.toString());
        }
        if (i2 < 0 || i2 > fVar.d()) {
            StringBuilder sbV2 = android.support.v4.media.session.a.v(i2, "end (", ") offset is outside of text region ");
            sbV2.append(fVar.d());
            throw new IndexOutOfBoundsException(sbV2.toString());
        }
        if (i >= i2) {
            throw new IllegalArgumentException(d0.p("Do not set reversed or empty range: ", i, " > ", i2));
        }
        this.d = i;
        this.e = i2;
    }

    public void g(int i, int i2) {
        androidx.compose.ui.text.android.selection.f fVar = (androidx.compose.ui.text.android.selection.f) this.f;
        if (i < 0 || i > fVar.d()) {
            StringBuilder sbV = android.support.v4.media.session.a.v(i, "start (", ") offset is outside of text region ");
            sbV.append(fVar.d());
            throw new IndexOutOfBoundsException(sbV.toString());
        }
        if (i2 < 0 || i2 > fVar.d()) {
            StringBuilder sbV2 = android.support.v4.media.session.a.v(i2, "end (", ") offset is outside of text region ");
            sbV2.append(fVar.d());
            throw new IndexOutOfBoundsException(sbV2.toString());
        }
        if (i > i2) {
            throw new IllegalArgumentException(d0.p("Do not set reversed range: ", i, " > ", i2));
        }
        i(i);
        h(i2);
    }

    public void h(int i) {
        if (i < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Cannot set selectionEnd to a negative value: ").toString());
        }
        this.c = i;
    }

    public void i(int i) {
        if (i < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Cannot set selectionStart to a negative value: ").toString());
        }
        this.b = i;
    }

    public long j() {
        int i = this.d;
        if (i == 0) {
            throw new NoSuchElementException();
        }
        long[] jArr = (long[]) this.f;
        int i2 = this.b;
        long j = jArr[i2];
        this.b = this.e & (i2 + 1);
        this.d = i - 1;
        return j;
    }

    public String toString() {
        switch (this.a) {
            case 0:
                return ((androidx.compose.ui.text.android.selection.f) this.f).toString();
            default:
                return super.toString();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2724v1
    public int zza() {
        return -1;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2724v1
    public int zzb() {
        return this.b;
    }

    public C1007j(int i, int i2, int i3, int i4, int i5, byte[] bArr) {
        this.b = i2;
        this.c = i3;
        this.d = i4;
        this.e = i5;
        this.f = bArr;
    }

    public C1007j(Mp mp) {
        Kn kn = mp.c;
        this.f = kn;
        kn.j(12);
        this.c = kn.C() & 255;
        this.b = kn.C();
    }

    public C1007j(C0995g c0995g, long j) {
        String str = c0995g.a;
        androidx.compose.ui.text.android.selection.f fVar = new androidx.compose.ui.text.android.selection.f(1, (byte) 0);
        fVar.d = str;
        fVar.b = -1;
        fVar.c = -1;
        this.f = fVar;
        this.b = androidx.compose.ui.text.K.e(j);
        this.c = androidx.compose.ui.text.K.d(j);
        this.d = -1;
        this.e = -1;
        int iE = androidx.compose.ui.text.K.e(j);
        int iD = androidx.compose.ui.text.K.d(j);
        String str2 = c0995g.a;
        if (iE >= 0 && iE <= str2.length()) {
            if (iD < 0 || iD > str2.length()) {
                StringBuilder sbV = android.support.v4.media.session.a.v(iD, "end (", ") offset is outside of text region ");
                sbV.append(str2.length());
                throw new IndexOutOfBoundsException(sbV.toString());
            }
            if (iE > iD) {
                throw new IllegalArgumentException(d0.p("Do not set reversed range: ", iE, " > ", iD));
            }
            return;
        }
        StringBuilder sbV2 = android.support.v4.media.session.a.v(iE, "start (", ") offset is outside of text region ");
        sbV2.append(str2.length());
        throw new IndexOutOfBoundsException(sbV2.toString());
    }
}
