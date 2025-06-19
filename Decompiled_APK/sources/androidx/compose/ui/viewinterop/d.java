package androidx.compose.ui.viewinterop;

import android.view.View;
import android.view.ViewGroup;
import androidx.compose.ui.layout.InterfaceC0894o;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.layout.L;
import androidx.compose.ui.layout.M;
import androidx.compose.ui.node.E;
import java.util.List;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d implements K {
    public final /* synthetic */ p a;
    public final /* synthetic */ E b;

    public d(p pVar, E e) {
        this.a = pVar;
        this.b = e;
    }

    @Override // androidx.compose.ui.layout.K
    public final int maxIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        p pVar = this.a;
        ViewGroup.LayoutParams layoutParams = pVar.getLayoutParams();
        Intrinsics.d(layoutParams);
        pVar.measure(i.k(pVar, 0, i, layoutParams.width), View.MeasureSpec.makeMeasureSpec(0, 0));
        return pVar.getMeasuredHeight();
    }

    @Override // androidx.compose.ui.layout.K
    public final int maxIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        int iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(0, 0);
        p pVar = this.a;
        ViewGroup.LayoutParams layoutParams = pVar.getLayoutParams();
        Intrinsics.d(layoutParams);
        pVar.measure(iMakeMeasureSpec, i.k(pVar, 0, i, layoutParams.height));
        return pVar.getMeasuredWidth();
    }

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final L mo1measure3p2s80s(M m, List list, long j) {
        p pVar = this.a;
        if (pVar.getChildCount() == 0) {
            return m.n0(androidx.compose.ui.unit.a.j(j), androidx.compose.ui.unit.a.i(j), V.c(), a.d);
        }
        if (androidx.compose.ui.unit.a.j(j) != 0) {
            pVar.getChildAt(0).setMinimumWidth(androidx.compose.ui.unit.a.j(j));
        }
        if (androidx.compose.ui.unit.a.i(j) != 0) {
            pVar.getChildAt(0).setMinimumHeight(androidx.compose.ui.unit.a.i(j));
        }
        int iJ = androidx.compose.ui.unit.a.j(j);
        int iH = androidx.compose.ui.unit.a.h(j);
        ViewGroup.LayoutParams layoutParams = pVar.getLayoutParams();
        Intrinsics.d(layoutParams);
        int iK = i.k(pVar, iJ, iH, layoutParams.width);
        int i = androidx.compose.ui.unit.a.i(j);
        int iG = androidx.compose.ui.unit.a.g(j);
        ViewGroup.LayoutParams layoutParams2 = pVar.getLayoutParams();
        Intrinsics.d(layoutParams2);
        pVar.measure(iK, i.k(pVar, i, iG, layoutParams2.height));
        return m.n0(pVar.getMeasuredWidth(), pVar.getMeasuredHeight(), V.c(), new c(pVar, this.b, 1));
    }

    @Override // androidx.compose.ui.layout.K
    public final int minIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        p pVar = this.a;
        ViewGroup.LayoutParams layoutParams = pVar.getLayoutParams();
        Intrinsics.d(layoutParams);
        pVar.measure(i.k(pVar, 0, i, layoutParams.width), View.MeasureSpec.makeMeasureSpec(0, 0));
        return pVar.getMeasuredHeight();
    }

    @Override // androidx.compose.ui.layout.K
    public final int minIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        int iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(0, 0);
        p pVar = this.a;
        ViewGroup.LayoutParams layoutParams = pVar.getLayoutParams();
        Intrinsics.d(layoutParams);
        pVar.measure(iMakeMeasureSpec, i.k(pVar, 0, i, layoutParams.height));
        return pVar.getMeasuredWidth();
    }
}
