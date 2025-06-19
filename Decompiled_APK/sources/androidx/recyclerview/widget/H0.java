package androidx.recyclerview.widget;

import android.os.Bundle;
import android.view.View;
import android.view.accessibility.AccessibilityEvent;
import androidx.core.view.C1038b;

/* loaded from: classes.dex */
public final class H0 extends C1038b {
    public final RecyclerView d;
    public final G0 e;

    public H0(RecyclerView recyclerView) {
        this.d = recyclerView;
        G0 g0 = this.e;
        if (g0 != null) {
            this.e = g0;
        } else {
            this.e = new G0(this);
        }
    }

    @Override // androidx.core.view.C1038b
    public final void c(View view, AccessibilityEvent accessibilityEvent) {
        super.c(view, accessibilityEvent);
        if (!(view instanceof RecyclerView) || this.d.R()) {
            return;
        }
        RecyclerView recyclerView = (RecyclerView) view;
        if (recyclerView.getLayoutManager() != null) {
            recyclerView.getLayoutManager().Y(accessibilityEvent);
        }
    }

    @Override // androidx.core.view.C1038b
    public final void d(View view, androidx.core.view.accessibility.e eVar) {
        this.a.onInitializeAccessibilityNodeInfo(view, eVar.a);
        RecyclerView recyclerView = this.d;
        if (recyclerView.R() || recyclerView.getLayoutManager() == null) {
            return;
        }
        AbstractC1381n0 layoutManager = recyclerView.getLayoutManager();
        RecyclerView recyclerView2 = layoutManager.b;
        layoutManager.Z(recyclerView2.c, recyclerView2.r1, eVar);
    }

    @Override // androidx.core.view.C1038b
    public final boolean g(View view, int i, Bundle bundle) {
        if (super.g(view, i, bundle)) {
            return true;
        }
        RecyclerView recyclerView = this.d;
        if (recyclerView.R() || recyclerView.getLayoutManager() == null) {
            return false;
        }
        return recyclerView.getLayoutManager().m0(i, bundle);
    }
}
