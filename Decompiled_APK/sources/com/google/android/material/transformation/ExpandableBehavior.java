package com.google.android.material.transformation;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.V;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import java.util.ArrayList;
import java.util.WeakHashMap;

@Deprecated
/* loaded from: classes2.dex */
public abstract class ExpandableBehavior extends androidx.coordinatorlayout.widget.b {
    public int a = 0;

    public ExpandableBehavior() {
    }

    @Override // androidx.coordinatorlayout.widget.b
    public abstract boolean f(CoordinatorLayout coordinatorLayout, View view, View view2);

    /* JADX WARN: Multi-variable type inference failed */
    @Override // androidx.coordinatorlayout.widget.b
    public final boolean h(CoordinatorLayout coordinatorLayout, View view, View view2) {
        Object obj = (com.google.android.material.expandable.a) view2;
        boolean z = ((FloatingActionButton) obj).o.b;
        if (z) {
            int i = this.a;
            if (i != 0 && i != 2) {
                return false;
            }
        } else if (this.a != 1) {
            return false;
        }
        this.a = z ? 1 : 2;
        w((View) obj, view, z, true);
        return true;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // androidx.coordinatorlayout.widget.b
    public final boolean l(CoordinatorLayout coordinatorLayout, View view, int i) {
        com.google.android.material.expandable.a aVar;
        boolean z;
        int i2;
        WeakHashMap weakHashMap = V.a;
        if (!view.isLaidOut()) {
            ArrayList arrayListK = coordinatorLayout.k(view);
            int size = arrayListK.size();
            int i3 = 0;
            while (true) {
                if (i3 >= size) {
                    aVar = null;
                    break;
                }
                View view2 = (View) arrayListK.get(i3);
                if (f(coordinatorLayout, view, view2)) {
                    aVar = (com.google.android.material.expandable.a) view2;
                    break;
                }
                i3++;
            }
            if (aVar != null && (!(z = ((FloatingActionButton) aVar).o.b) ? this.a == 1 : !((i2 = this.a) != 0 && i2 != 2))) {
                int i4 = z ? 1 : 2;
                this.a = i4;
                view.getViewTreeObserver().addOnPreDrawListener(new a(this, view, i4, aVar));
            }
        }
        return false;
    }

    public abstract void w(View view, View view2, boolean z, boolean z2);

    public ExpandableBehavior(Context context, AttributeSet attributeSet) {
    }
}
