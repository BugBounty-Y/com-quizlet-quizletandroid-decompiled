package androidx.compose.runtime.changelist;

import androidx.compose.runtime.D0;
import androidx.compose.runtime.InterfaceC0790d;
import com.google.android.gms.internal.mlkit_vision_barcode.E4;
import java.util.Arrays;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class L extends E4 {
    public int c;
    public int e;
    public int g;
    public J[] b = new J[16];
    public int[] d = new int[16];
    public Object[] f = new Object[16];

    public final void b() {
        this.c = 0;
        this.e = 0;
        Object[] objArr = this.f;
        int i = this.g;
        Intrinsics.checkNotNullParameter(objArr, "<this>");
        Arrays.fill(objArr, 0, i, (Object) null);
        this.g = 0;
    }

    public final void c(InterfaceC0790d interfaceC0790d, D0 d0, androidx.compose.runtime.internal.j jVar) {
        int i;
        int i2;
        if (e()) {
            K k = new K(this);
            do {
                L l = (L) k.e;
                l.b[k.b].a(k, interfaceC0790d, d0, jVar);
                int i3 = k.b;
                i = l.c;
                if (i3 >= i) {
                    break;
                }
                J j = l.b[i3];
                k.c += j.a;
                k.d += j.b;
                i2 = i3 + 1;
                k.b = i2;
            } while (i2 < i);
        }
        b();
    }

    public final boolean d() {
        return this.c == 0;
    }

    public final boolean e() {
        return this.c != 0;
    }

    public final void f(J j) {
        int i = this.c;
        J[] jArr = this.b;
        if (i == jArr.length) {
            J[] jArr2 = new J[(i > 1024 ? 1024 : i) + i];
            System.arraycopy(jArr, 0, jArr2, 0, i);
            this.b = jArr2;
        }
        int i2 = this.e + j.a;
        int[] iArr = this.d;
        int length = iArr.length;
        if (i2 > length) {
            int i3 = (length > 1024 ? 1024 : length) + length;
            if (i3 >= i2) {
                i2 = i3;
            }
            int[] iArr2 = new int[i2];
            C4930v.e(0, 0, length, iArr, iArr2);
            this.d = iArr2;
        }
        int i4 = this.g;
        int i5 = j.b;
        int i6 = i4 + i5;
        Object[] objArr = this.f;
        int length2 = objArr.length;
        if (i6 > length2) {
            int i7 = (length2 <= 1024 ? length2 : 1024) + length2;
            if (i7 >= i6) {
                i6 = i7;
            }
            Object[] objArr2 = new Object[i6];
            System.arraycopy(objArr, 0, objArr2, 0, length2);
            this.f = objArr2;
        }
        J[] jArr3 = this.b;
        int i8 = this.c;
        this.c = i8 + 1;
        jArr3[i8] = j;
        this.e += j.a;
        this.g += i5;
    }
}
