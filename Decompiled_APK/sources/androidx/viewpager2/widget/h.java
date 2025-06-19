package androidx.viewpager2.widget;

import android.content.Context;
import android.graphics.Rect;
import android.os.Bundle;
import android.view.View;
import androidx.recyclerview.widget.AbstractC1381n0;
import androidx.recyclerview.widget.B0;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.v0;
import androidx.webkit.internal.p;

/* loaded from: classes.dex */
public final class h extends LinearLayoutManager {
    public final /* synthetic */ ViewPager2 E;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(ViewPager2 viewPager2, Context context) {
        super(context);
        this.E = viewPager2;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public final void I0(B0 b0, int[] iArr) {
        ViewPager2 viewPager2 = this.E;
        int offscreenPageLimit = viewPager2.getOffscreenPageLimit();
        if (offscreenPageLimit == -1) {
            super.I0(b0, iArr);
            return;
        }
        int pageSize = viewPager2.getPageSize() * offscreenPageLimit;
        iArr[0] = pageSize;
        iArr[1] = pageSize;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final void Z(v0 v0Var, B0 b0, androidx.core.view.accessibility.e eVar) {
        super.Z(v0Var, b0, eVar);
        this.E.t.getClass();
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void b0(v0 v0Var, B0 b0, View view, androidx.core.view.accessibility.e eVar) {
        int iK;
        int iK2;
        ViewPager2 viewPager2 = (ViewPager2) this.E.t.d;
        if (viewPager2.getOrientation() == 1) {
            viewPager2.g.getClass();
            iK = AbstractC1381n0.K(view);
        } else {
            iK = 0;
        }
        if (viewPager2.getOrientation() == 0) {
            viewPager2.g.getClass();
            iK2 = AbstractC1381n0.K(view);
        } else {
            iK2 = 0;
        }
        eVar.k(p.r(iK, 1, iK2, 1, false));
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final boolean n0(v0 v0Var, B0 b0, int i, Bundle bundle) {
        this.E.t.getClass();
        return super.n0(v0Var, b0, i, bundle);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final boolean s0(RecyclerView recyclerView, View view, Rect rect, boolean z, boolean z2) {
        return false;
    }
}
