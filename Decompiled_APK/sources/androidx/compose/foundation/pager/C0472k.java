package androidx.compose.foundation.pager;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.ui.layout.W;
import java.util.List;

/* renamed from: androidx.compose.foundation.pager.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0472k {
    public final int a;
    public final List b;
    public final long c;
    public final Object d;
    public final androidx.compose.ui.c e;
    public final androidx.compose.ui.h f;
    public final androidx.compose.ui.unit.k g;
    public final boolean h;
    public final boolean i;
    public final int j;
    public final int[] k;
    public int l;
    public int m;

    public C0472k(int i, int i2, List list, long j, Object obj, EnumC0320d0 enumC0320d0, androidx.compose.ui.c cVar, androidx.compose.ui.h hVar, androidx.compose.ui.unit.k kVar, boolean z) {
        this.a = i;
        this.b = list;
        this.c = j;
        this.d = obj;
        this.e = cVar;
        this.f = hVar;
        this.g = kVar;
        this.h = z;
        this.i = enumC0320d0 == EnumC0320d0.a;
        int size = list.size();
        int iMax = 0;
        for (int i3 = 0; i3 < size; i3++) {
            W w = (W) list.get(i3);
            iMax = Math.max(iMax, !this.i ? w.b : w.a);
        }
        this.j = iMax;
        this.k = new int[this.b.size() * 2];
        this.m = Integer.MIN_VALUE;
    }

    public final void a(int i) {
        this.l += i;
        int[] iArr = this.k;
        int length = iArr.length;
        for (int i2 = 0; i2 < length; i2++) {
            boolean z = this.i;
            if ((z && i2 % 2 == 1) || (!z && i2 % 2 == 0)) {
                iArr[i2] = iArr[i2] + i;
            }
        }
    }

    public final void b(int i, int i2, int i3) {
        int i4;
        this.l = i;
        boolean z = this.i;
        this.m = z ? i3 : i2;
        List list = this.b;
        int size = list.size();
        for (int i5 = 0; i5 < size; i5++) {
            W w = (W) list.get(i5);
            int i6 = i5 * 2;
            int[] iArr = this.k;
            if (z) {
                androidx.compose.ui.c cVar = this.e;
                if (cVar == null) {
                    throw new IllegalArgumentException("null horizontalAlignment");
                }
                iArr[i6] = cVar.a(w.a, i2, this.g);
                iArr[i6 + 1] = i;
                i4 = w.b;
            } else {
                iArr[i6] = i;
                int i7 = i6 + 1;
                androidx.compose.ui.h hVar = this.f;
                if (hVar == null) {
                    throw new IllegalArgumentException("null verticalAlignment");
                }
                iArr[i7] = hVar.a(w.b, i3);
                i4 = w.a;
            }
            i += i4;
        }
    }
}
