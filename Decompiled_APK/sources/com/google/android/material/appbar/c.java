package com.google.android.material.appbar;

import android.os.Bundle;
import android.view.View;
import android.widget.ScrollView;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.C1038b;
import com.google.android.material.appbar.AppBarLayout;

/* loaded from: classes2.dex */
public final class c extends C1038b {
    public final /* synthetic */ AppBarLayout d;
    public final /* synthetic */ CoordinatorLayout e;
    public final /* synthetic */ AppBarLayout.BaseBehavior f;

    public c(CoordinatorLayout coordinatorLayout, AppBarLayout.BaseBehavior baseBehavior, AppBarLayout appBarLayout) {
        this.f = baseBehavior;
        this.d = appBarLayout;
        this.e = coordinatorLayout;
    }

    @Override // androidx.core.view.C1038b
    public final void d(View view, androidx.core.view.accessibility.e eVar) {
        AppBarLayout.BaseBehavior baseBehavior;
        View viewB;
        this.a.onInitializeAccessibilityNodeInfo(view, eVar.a);
        eVar.i(ScrollView.class.getName());
        AppBarLayout appBarLayout = this.d;
        if (appBarLayout.getTotalScrollRange() == 0 || (viewB = AppBarLayout.BaseBehavior.B((baseBehavior = this.f), this.e)) == null) {
            return;
        }
        int childCount = appBarLayout.getChildCount();
        for (int i = 0; i < childCount; i++) {
            if (((e) appBarLayout.getChildAt(i).getLayoutParams()).a != 0) {
                if (baseBehavior.y() != (-appBarLayout.getTotalScrollRange())) {
                    eVar.b(androidx.core.view.accessibility.d.h);
                    eVar.l(true);
                }
                if (baseBehavior.y() != 0) {
                    if (!viewB.canScrollVertically(-1)) {
                        eVar.b(androidx.core.view.accessibility.d.i);
                        eVar.l(true);
                        return;
                    } else {
                        if ((-appBarLayout.getDownNestedPreScrollRange()) != 0) {
                            eVar.b(androidx.core.view.accessibility.d.i);
                            eVar.l(true);
                            return;
                        }
                        return;
                    }
                }
                return;
            }
        }
    }

    @Override // androidx.core.view.C1038b
    public final boolean g(View view, int i, Bundle bundle) {
        AppBarLayout appBarLayout = this.d;
        if (i == 4096) {
            appBarLayout.setExpanded(false);
            return true;
        }
        if (i != 8192) {
            return super.g(view, i, bundle);
        }
        AppBarLayout.BaseBehavior baseBehavior = this.f;
        if (baseBehavior.y() != 0) {
            View viewB = AppBarLayout.BaseBehavior.B(baseBehavior, this.e);
            if (!viewB.canScrollVertically(-1)) {
                appBarLayout.setExpanded(true);
                return true;
            }
            int i2 = -appBarLayout.getDownNestedPreScrollRange();
            if (i2 != 0) {
                CoordinatorLayout coordinatorLayout = this.e;
                AppBarLayout appBarLayout2 = this.d;
                this.f.E(coordinatorLayout, appBarLayout2, viewB, i2, new int[]{0, 0});
                return true;
            }
        }
        return false;
    }
}
