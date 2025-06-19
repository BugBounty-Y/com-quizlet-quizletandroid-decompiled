package androidx.recyclerview.widget;

import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import androidx.core.view.C1038b;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class G0 extends C1038b {
    public final H0 d;
    public final WeakHashMap e = new WeakHashMap();

    public G0(H0 h0) {
        this.d = h0;
    }

    @Override // androidx.core.view.C1038b
    public final boolean a(View view, AccessibilityEvent accessibilityEvent) {
        C1038b c1038b = (C1038b) this.e.get(view);
        return c1038b != null ? c1038b.a(view, accessibilityEvent) : this.a.dispatchPopulateAccessibilityEvent(view, accessibilityEvent);
    }

    @Override // androidx.core.view.C1038b
    public final com.airbnb.lottie.network.c b(View view) {
        C1038b c1038b = (C1038b) this.e.get(view);
        return c1038b != null ? c1038b.b(view) : super.b(view);
    }

    @Override // androidx.core.view.C1038b
    public final void c(View view, AccessibilityEvent accessibilityEvent) {
        C1038b c1038b = (C1038b) this.e.get(view);
        if (c1038b != null) {
            c1038b.c(view, accessibilityEvent);
        } else {
            super.c(view, accessibilityEvent);
        }
    }

    @Override // androidx.core.view.C1038b
    public final void d(View view, androidx.core.view.accessibility.e eVar) {
        H0 h0 = this.d;
        boolean zR = h0.d.R();
        View.AccessibilityDelegate accessibilityDelegate = this.a;
        AccessibilityNodeInfo accessibilityNodeInfo = eVar.a;
        if (!zR) {
            RecyclerView recyclerView = h0.d;
            if (recyclerView.getLayoutManager() != null) {
                recyclerView.getLayoutManager().a0(view, eVar);
                C1038b c1038b = (C1038b) this.e.get(view);
                if (c1038b != null) {
                    c1038b.d(view, eVar);
                    return;
                } else {
                    accessibilityDelegate.onInitializeAccessibilityNodeInfo(view, accessibilityNodeInfo);
                    return;
                }
            }
        }
        accessibilityDelegate.onInitializeAccessibilityNodeInfo(view, accessibilityNodeInfo);
    }

    @Override // androidx.core.view.C1038b
    public final void e(View view, AccessibilityEvent accessibilityEvent) {
        C1038b c1038b = (C1038b) this.e.get(view);
        if (c1038b != null) {
            c1038b.e(view, accessibilityEvent);
        } else {
            super.e(view, accessibilityEvent);
        }
    }

    @Override // androidx.core.view.C1038b
    public final boolean f(ViewGroup viewGroup, View view, AccessibilityEvent accessibilityEvent) {
        C1038b c1038b = (C1038b) this.e.get(viewGroup);
        return c1038b != null ? c1038b.f(viewGroup, view, accessibilityEvent) : this.a.onRequestSendAccessibilityEvent(viewGroup, view, accessibilityEvent);
    }

    @Override // androidx.core.view.C1038b
    public final boolean g(View view, int i, Bundle bundle) {
        H0 h0 = this.d;
        if (!h0.d.R()) {
            RecyclerView recyclerView = h0.d;
            if (recyclerView.getLayoutManager() != null) {
                C1038b c1038b = (C1038b) this.e.get(view);
                if (c1038b != null) {
                    if (c1038b.g(view, i, bundle)) {
                        return true;
                    }
                } else if (super.g(view, i, bundle)) {
                    return true;
                }
                v0 v0Var = recyclerView.getLayoutManager().b.c;
                return false;
            }
        }
        return super.g(view, i, bundle);
    }

    @Override // androidx.core.view.C1038b
    public final void h(View view, int i) {
        C1038b c1038b = (C1038b) this.e.get(view);
        if (c1038b != null) {
            c1038b.h(view, i);
        } else {
            super.h(view, i);
        }
    }

    @Override // androidx.core.view.C1038b
    public final void i(View view, AccessibilityEvent accessibilityEvent) {
        C1038b c1038b = (C1038b) this.e.get(view);
        if (c1038b != null) {
            c1038b.i(view, accessibilityEvent);
        } else {
            super.i(view, accessibilityEvent);
        }
    }
}
