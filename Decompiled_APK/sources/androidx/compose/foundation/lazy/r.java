package androidx.compose.foundation.lazy;

import androidx.compose.foundation.lazy.layout.K;
import androidx.compose.foundation.lazy.layout.V;
import androidx.compose.runtime.L0;
import androidx.compose.ui.layout.W;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;

/* loaded from: classes.dex */
public final class r implements V {
    public final int a;
    public final List b;
    public final boolean c;
    public final androidx.compose.ui.c d;
    public final androidx.compose.ui.h e;
    public final androidx.compose.ui.unit.k f;
    public final int g;
    public final int h;
    public final int i;
    public final long j;
    public final Object k;
    public final Object l;
    public final K m;
    public final long n;
    public int o;
    public final int p;
    public final int q;
    public final int r;
    public boolean s;
    public int t = Integer.MIN_VALUE;
    public int u;
    public int v;
    public final int[] w;

    public r(int i, List list, boolean z, androidx.compose.ui.c cVar, androidx.compose.ui.h hVar, androidx.compose.ui.unit.k kVar, int i2, int i3, int i4, long j, Object obj, Object obj2, K k, long j2) {
        this.a = i;
        this.b = list;
        this.c = z;
        this.d = cVar;
        this.e = hVar;
        this.f = kVar;
        this.g = i2;
        this.h = i3;
        this.i = i4;
        this.j = j;
        this.k = obj;
        this.l = obj2;
        this.m = k;
        this.n = j2;
        int size = list.size();
        int i5 = 0;
        int iMax = 0;
        for (int i6 = 0; i6 < size; i6++) {
            W w = (W) list.get(i6);
            boolean z2 = this.c;
            i5 += z2 ? w.b : w.a;
            iMax = Math.max(iMax, !z2 ? w.b : w.a);
        }
        this.p = i5;
        int i7 = i5 + this.i;
        this.q = i7 >= 0 ? i7 : 0;
        this.r = iMax;
        this.w = new int[this.b.size() * 2];
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final int a() {
        return this.b.size();
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final void b(int i, int i2, int i3, int i4) {
        m(i, i3, i4);
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final int c() {
        return this.q;
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final int d() {
        return 1;
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final Object e(int i) {
        return ((W) this.b.get(i)).G();
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final long f() {
        return this.n;
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final boolean g() {
        return this.c;
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final int getIndex() {
        return this.a;
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final Object getKey() {
        return this.k;
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final void h() {
        this.s = true;
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final long i(int i) {
        int i2 = i * 2;
        int[] iArr = this.w;
        return P5.b(iArr[i2], iArr[i2 + 1]);
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final int j() {
        return 0;
    }

    public final int k(long j) {
        return (int) (this.c ? j & 4294967295L : j >> 32);
    }

    public final void l(androidx.compose.ui.layout.V v, boolean z) {
        List list;
        int i;
        if (this.t == Integer.MIN_VALUE) {
            throw new IllegalArgumentException("position() should be called first");
        }
        List list2 = this.b;
        int size = list2.size();
        int i2 = 0;
        while (i2 < size) {
            W w = (W) list2.get(i2);
            int i3 = this.u;
            boolean z2 = this.c;
            int i4 = i3 - (z2 ? w.b : w.a);
            int i5 = this.v;
            long jI = i(i2);
            androidx.compose.foundation.lazy.layout.E eA = this.m.a(i2, this.k);
            androidx.compose.ui.graphics.layer.b bVar = null;
            if (eA != null) {
                if (z) {
                    eA.r = jI;
                    list = list2;
                    i = size;
                } else {
                    list = list2;
                    i = size;
                    if (!androidx.compose.ui.unit.h.b(eA.r, androidx.compose.foundation.lazy.layout.E.s)) {
                        jI = eA.r;
                    }
                    long jD = androidx.compose.ui.unit.h.d(jI, ((androidx.compose.ui.unit.h) ((L0) eA.q).getValue()).a);
                    if (((k(jI) <= i4 && k(jD) <= i4) || (k(jI) >= i5 && k(jD) >= i5)) && ((Boolean) ((L0) eA.h).getValue()).booleanValue()) {
                        kotlinx.coroutines.E.A(eA.a, null, null, new androidx.compose.foundation.lazy.layout.A(eA, null), 3);
                    }
                    jI = jD;
                }
                bVar = eA.n;
            } else {
                list = list2;
                i = size;
            }
            long jD2 = androidx.compose.ui.unit.h.d(jI, this.j);
            if (!z && eA != null) {
                eA.m = jD2;
            }
            if (z2) {
                if (bVar != null) {
                    v.getClass();
                    androidx.compose.ui.layout.V.a(v, w);
                    w.r0(androidx.compose.ui.unit.h.d(jD2, w.e), DefinitionKt.NO_Float_VALUE, bVar);
                } else {
                    androidx.compose.ui.layout.V.j(v, w, jD2);
                }
            } else if (bVar == null) {
                androidx.compose.ui.layout.V.h(v, w, jD2);
            } else if (v.b() == androidx.compose.ui.unit.k.a || v.c() == 0) {
                androidx.compose.ui.layout.V.a(v, w);
                w.r0(androidx.compose.ui.unit.h.d(jD2, w.e), DefinitionKt.NO_Float_VALUE, bVar);
            } else {
                long jB = P5.b((v.c() - w.a) - ((int) (jD2 >> 32)), (int) (jD2 & 4294967295L));
                androidx.compose.ui.layout.V.a(v, w);
                w.r0(androidx.compose.ui.unit.h.d(jB, w.e), DefinitionKt.NO_Float_VALUE, bVar);
            }
            i2++;
            list2 = list;
            size = i;
        }
    }

    public final void m(int i, int i2, int i3) {
        int i4;
        this.o = i;
        boolean z = this.c;
        this.t = z ? i3 : i2;
        List list = this.b;
        int size = list.size();
        for (int i5 = 0; i5 < size; i5++) {
            W w = (W) list.get(i5);
            int i6 = i5 * 2;
            int[] iArr = this.w;
            if (z) {
                androidx.compose.ui.c cVar = this.d;
                if (cVar == null) {
                    throw new IllegalArgumentException("null horizontalAlignment when isVertical == true");
                }
                iArr[i6] = cVar.a(w.a, i2, this.f);
                iArr[i6 + 1] = i;
                i4 = w.b;
            } else {
                iArr[i6] = i;
                int i7 = i6 + 1;
                androidx.compose.ui.h hVar = this.e;
                if (hVar == null) {
                    throw new IllegalArgumentException("null verticalAlignment when isVertical == false");
                }
                iArr[i7] = hVar.a(w.b, i3);
                i4 = w.a;
            }
            i += i4;
        }
        this.u = -this.g;
        this.v = this.t + this.h;
    }
}
