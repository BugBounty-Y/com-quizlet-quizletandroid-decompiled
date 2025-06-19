package androidx.compose.foundation.lazy.grid;

import androidx.compose.foundation.lazy.layout.K;
import androidx.compose.foundation.lazy.layout.U;
import androidx.compose.foundation.lazy.layout.V;
import androidx.compose.foundation.lazy.layout.W;
import java.util.List;

/* loaded from: classes.dex */
public final class l implements W {
    public final j a;
    public final U b;
    public final int c;
    public final /* synthetic */ U d;
    public final /* synthetic */ A e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;
    public final /* synthetic */ long h;

    public l(j jVar, U u, int i, A a, int i2, int i3, long j) {
        this.d = u;
        this.e = a;
        this.f = i2;
        this.g = i3;
        this.h = j;
        this.a = jVar;
        this.b = u;
        this.c = i;
    }

    @Override // androidx.compose.foundation.lazy.layout.W
    public final V a(long j, int i, int i2, int i3) {
        return b(i, j, i2, i3, this.c);
    }

    public final r b(int i, long j, int i2, int i3, int i4) {
        int i5;
        j jVar = this.a;
        Object objB = jVar.b(i);
        Object objI = jVar.b.i(i);
        List listB = this.b.b(i, j);
        if (androidx.compose.ui.unit.a.f(j)) {
            i5 = androidx.compose.ui.unit.a.j(j);
        } else {
            if (!androidx.compose.ui.unit.a.e(j)) {
                throw new IllegalArgumentException("does not have fixed height");
            }
            i5 = androidx.compose.ui.unit.a.i(j);
        }
        int i6 = i5;
        androidx.compose.ui.unit.k layoutDirection = this.d.b.getLayoutDirection();
        K k = this.e.k;
        return new r(i, objB, i6, i4, layoutDirection, this.f, this.g, listB, this.h, objI, k, j, i2, i3);
    }
}
