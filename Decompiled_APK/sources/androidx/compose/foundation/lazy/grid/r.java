package androidx.compose.foundation.lazy.grid;

import androidx.compose.foundation.lazy.layout.K;
import androidx.compose.foundation.lazy.layout.V;
import androidx.compose.ui.layout.W;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import java.util.List;

/* loaded from: classes.dex */
public final class r implements V {
    public final int a;
    public final Object b;
    public final int c;
    public final androidx.compose.ui.unit.k d;
    public final int e;
    public final int f;
    public final List g;
    public final long h;
    public final Object i;
    public final K j;
    public final long k;
    public final int l;
    public final int m;
    public final int n;
    public final int o;
    public int p = Integer.MIN_VALUE;
    public int q;
    public int r;
    public final long s;
    public long t;
    public int u;
    public int v;
    public boolean w;

    public r(int i, Object obj, int i2, int i3, androidx.compose.ui.unit.k kVar, int i4, int i5, List list, long j, Object obj2, K k, long j2, int i6, int i7) {
        this.a = i;
        this.b = obj;
        this.c = i2;
        this.d = kVar;
        this.e = i4;
        this.f = i5;
        this.g = list;
        this.h = j;
        this.i = obj2;
        this.j = k;
        this.k = j2;
        this.l = i6;
        this.m = i7;
        int size = list.size();
        int iMax = 0;
        for (int i8 = 0; i8 < size; i8++) {
            iMax = Math.max(iMax, ((W) list.get(i8)).b);
        }
        this.n = iMax;
        int i9 = i3 + iMax;
        this.o = i9 >= 0 ? i9 : 0;
        this.s = R5.a(this.c, iMax);
        this.t = 0L;
        this.u = -1;
        this.v = -1;
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final int a() {
        return this.g.size();
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final void b(int i, int i2, int i3, int i4) {
        k(i, i2, i3, i4, -1, -1);
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final int c() {
        return this.o;
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final int d() {
        return this.m;
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final Object e(int i) {
        return ((W) this.g.get(i)).G();
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final long f() {
        return this.k;
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final boolean g() {
        return true;
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final int getIndex() {
        return this.a;
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final Object getKey() {
        return this.b;
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final void h() {
        this.w = true;
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final long i(int i) {
        return this.t;
    }

    @Override // androidx.compose.foundation.lazy.layout.V
    public final int j() {
        return this.l;
    }

    public final void k(int i, int i2, int i3, int i4, int i5, int i6) {
        this.p = i4;
        if (this.d == androidx.compose.ui.unit.k.b) {
            i2 = (i3 - i2) - this.c;
        }
        this.t = P5.b(i2, i);
        this.u = i5;
        this.v = i6;
        this.q = -this.e;
        this.r = this.p + this.f;
    }
}
