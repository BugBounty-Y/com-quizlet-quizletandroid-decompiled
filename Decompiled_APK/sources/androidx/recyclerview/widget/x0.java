package androidx.recyclerview.widget;

import java.util.ArrayList;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class x0 extends AbstractC1365f0 {
    public final /* synthetic */ RecyclerView a;

    public x0(RecyclerView recyclerView) {
        this.a = recyclerView;
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public final void a() {
        RecyclerView recyclerView = this.a;
        recyclerView.l(null);
        recyclerView.r1.f = true;
        recyclerView.b0(true);
        if (recyclerView.e.h()) {
            return;
        }
        recyclerView.requestLayout();
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public final void c(int i, int i2, Object obj) {
        RecyclerView recyclerView = this.a;
        recyclerView.l(null);
        androidx.navigation.internal.m mVar = recyclerView.e;
        if (i2 < 1) {
            mVar.getClass();
            return;
        }
        ArrayList arrayList = (ArrayList) mVar.b;
        arrayList.add(mVar.j(obj, 4, i, i2));
        mVar.c |= 4;
        if (arrayList.size() == 1) {
            h();
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public final void d(int i, int i2) {
        RecyclerView recyclerView = this.a;
        recyclerView.l(null);
        androidx.navigation.internal.m mVar = recyclerView.e;
        if (i2 < 1) {
            mVar.getClass();
            return;
        }
        ArrayList arrayList = (ArrayList) mVar.b;
        arrayList.add(mVar.j(null, 1, i, i2));
        mVar.c |= 1;
        if (arrayList.size() == 1) {
            h();
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public final void e(int i, int i2) {
        RecyclerView recyclerView = this.a;
        recyclerView.l(null);
        androidx.navigation.internal.m mVar = recyclerView.e;
        mVar.getClass();
        if (i == i2) {
            return;
        }
        ArrayList arrayList = (ArrayList) mVar.b;
        arrayList.add(mVar.j(null, 8, i, i2));
        mVar.c |= 8;
        if (arrayList.size() == 1) {
            h();
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public final void f(int i, int i2) {
        RecyclerView recyclerView = this.a;
        recyclerView.l(null);
        androidx.navigation.internal.m mVar = recyclerView.e;
        if (i2 < 1) {
            mVar.getClass();
            return;
        }
        ArrayList arrayList = (ArrayList) mVar.b;
        arrayList.add(mVar.j(null, 2, i, i2));
        mVar.c |= 2;
        if (arrayList.size() == 1) {
            h();
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public final void g() {
        AbstractC1361d0 abstractC1361d0;
        RecyclerView recyclerView = this.a;
        if (recyclerView.d == null || (abstractC1361d0 = recyclerView.m) == null || !abstractC1361d0.canRestoreState()) {
            return;
        }
        recyclerView.requestLayout();
    }

    public final void h() {
        RecyclerView recyclerView = this.a;
        if (recyclerView.t && recyclerView.s) {
            WeakHashMap weakHashMap = androidx.core.view.V.a;
            recyclerView.postOnAnimation(recyclerView.i);
        } else {
            recyclerView.A = true;
            recyclerView.requestLayout();
        }
    }
}
