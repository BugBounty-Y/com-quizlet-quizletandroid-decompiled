package androidx.compose.runtime;

import androidx.collection.C0223v;
import java.util.ArrayList;

/* renamed from: androidx.compose.runtime.i0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0801i0 {
    public final ArrayList a;
    public final int b;
    public int c;
    public final ArrayList d;
    public final C0223v e;
    public final kotlin.u f;

    public C0801i0(int i, ArrayList arrayList) {
        this.a = arrayList;
        this.b = i;
        if (i < 0) {
            AbstractC0805k0.a("Invalid start index");
        }
        this.d = new ArrayList();
        C0223v c0223v = new C0223v();
        int size = arrayList.size();
        int i2 = 0;
        for (int i3 = 0; i3 < size; i3++) {
            S s = (S) this.a.get(i3);
            int i4 = s.c;
            int i5 = s.d;
            c0223v.h(i4, new K(i3, i2, i5));
            i2 += i5;
        }
        this.e = c0223v;
        this.f = kotlin.l.b(new androidx.compose.animation.core.K(this, 24));
    }

    public final boolean a(int i, int i2) {
        int i3;
        C0223v c0223v = this.e;
        K k = (K) c0223v.e(i);
        if (k == null) {
            return false;
        }
        int i4 = k.b;
        int i5 = i2 - k.c;
        k.c = i2;
        if (i5 == 0) {
            return true;
        }
        Object[] objArr = c0223v.c;
        long[] jArr = c0223v.a;
        int length = jArr.length - 2;
        if (length < 0) {
            return true;
        }
        int i6 = 0;
        while (true) {
            long j = jArr[i6];
            if ((((~j) << 7) & j & (-9187201950435737472L)) != -9187201950435737472L) {
                int i7 = 8 - ((~(i6 - length)) >>> 31);
                for (int i8 = 0; i8 < i7; i8++) {
                    if ((255 & j) < 128) {
                        K k2 = (K) objArr[(i6 << 3) + i8];
                        if (k2.b >= i4 && !k2.equals(k) && (i3 = k2.b + i5) >= 0) {
                            k2.b = i3;
                        }
                    }
                    j >>= 8;
                }
                if (i7 != 8) {
                    return true;
                }
            }
            if (i6 == length) {
                return true;
            }
            i6++;
        }
    }
}
