package com.google.android.material.behavior;

import android.view.MotionEvent;
import android.view.View;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.coordinatorlayout.widget.b;
import androidx.core.view.V;
import androidx.customview.widget.d;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class SwipeDismissBehavior<V extends View> extends b {
    public d a;
    public com.airbnb.lottie.network.d b;
    public boolean c;
    public boolean d;
    public int e = 2;
    public float f = DefinitionKt.NO_Float_VALUE;
    public float g = 0.5f;
    public final a h = new a(this);

    @Override // androidx.coordinatorlayout.widget.b
    public boolean k(CoordinatorLayout coordinatorLayout, View view, MotionEvent motionEvent) {
        boolean zP = this.c;
        int actionMasked = motionEvent.getActionMasked();
        if (actionMasked == 0) {
            zP = coordinatorLayout.p(view, (int) motionEvent.getX(), (int) motionEvent.getY());
            this.c = zP;
        } else if (actionMasked == 1 || actionMasked == 3) {
            this.c = false;
        }
        if (zP) {
            if (this.a == null) {
                this.a = new d(coordinatorLayout.getContext(), coordinatorLayout, this.h);
            }
            if (!this.d && this.a.p(motionEvent)) {
                return true;
            }
        }
        return false;
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final boolean l(CoordinatorLayout coordinatorLayout, View view, int i) {
        WeakHashMap weakHashMap = V.a;
        if (view.getImportantForAccessibility() == 0) {
            view.setImportantForAccessibility(1);
            V.l(1048576, view);
            V.i(0, view);
            if (w(view)) {
                V.m(view, androidx.core.view.accessibility.d.l, new com.google.android.gms.internal.instantapps.a(this, 29));
            }
        }
        return false;
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final boolean v(CoordinatorLayout coordinatorLayout, View view, MotionEvent motionEvent) {
        if (this.a == null) {
            return false;
        }
        if (this.d && motionEvent.getActionMasked() == 3) {
            return true;
        }
        this.a.j(motionEvent);
        return true;
    }

    public boolean w(View view) {
        return true;
    }
}
