package androidx.compose.ui.platform;

import android.view.View;
import androidx.core.view.C1060q;
import java.util.WeakHashMap;
import kotlin.collections.C4930v;

/* loaded from: classes.dex */
public final class B0 implements androidx.compose.ui.input.nestedscroll.a {
    public final View a;
    public final C1060q b;
    public final int[] c;

    public B0(View view) {
        this.a = view;
        C1060q c1060q = new C1060q(view);
        c1060q.g(true);
        this.b = c1060q;
        this.c = new int[2];
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        androidx.core.view.L.l(view, true);
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final long L(int i, long j) {
        if (!this.b.h(N.n(j), (i == 1 ? 1 : 0) ^ 1)) {
            return 0L;
        }
        int[] iArr = this.c;
        C4930v.p(iArr, 0);
        this.b.c(N.s(androidx.compose.ui.geometry.b.d(j)), N.s(androidx.compose.ui.geometry.b.e(j)), (i == 1 ? 1 : 0) ^ 1, this.c, null);
        return N.q(iArr, j);
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final Object i0(long j, kotlin.coroutines.h hVar) {
        float fB = androidx.compose.ui.unit.o.b(j) * (-1.0f);
        float fC = androidx.compose.ui.unit.o.c(j) * (-1.0f);
        C1060q c1060q = this.b;
        if (!c1060q.b(fB, fC)) {
            j = 0;
        }
        if (c1060q.f(0)) {
            c1060q.i(0);
        }
        if (c1060q.f(1)) {
            c1060q.i(1);
        }
        return new androidx.compose.ui.unit.o(j);
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final Object p(long j, long j2, kotlin.coroutines.h hVar) {
        float fB = androidx.compose.ui.unit.o.b(j2) * (-1.0f);
        float fC = androidx.compose.ui.unit.o.c(j2) * (-1.0f);
        C1060q c1060q = this.b;
        if (!c1060q.a(fB, fC, true)) {
            j2 = 0;
        }
        if (c1060q.f(0)) {
            c1060q.i(0);
        }
        if (c1060q.f(1)) {
            c1060q.i(1);
        }
        return new androidx.compose.ui.unit.o(j2);
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final long s0(long j, long j2, int i) {
        if (!this.b.h(N.n(j2), (i == 1 ? 1 : 0) ^ 1)) {
            return 0L;
        }
        int[] iArr = this.c;
        C4930v.p(iArr, 0);
        this.b.d(N.s(androidx.compose.ui.geometry.b.d(j)), N.s(androidx.compose.ui.geometry.b.e(j)), N.s(androidx.compose.ui.geometry.b.d(j2)), N.s(androidx.compose.ui.geometry.b.e(j2)), null, (i == 1 ? 1 : 0) ^ 1, this.c);
        return N.q(iArr, j2);
    }
}
