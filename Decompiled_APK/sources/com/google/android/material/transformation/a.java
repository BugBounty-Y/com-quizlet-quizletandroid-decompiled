package com.google.android.material.transformation;

import android.view.View;
import android.view.ViewTreeObserver;
import com.google.android.material.floatingactionbutton.FloatingActionButton;

/* loaded from: classes2.dex */
public final class a implements ViewTreeObserver.OnPreDrawListener {
    public final /* synthetic */ View a;
    public final /* synthetic */ int b;
    public final /* synthetic */ com.google.android.material.expandable.a c;
    public final /* synthetic */ ExpandableBehavior d;

    public a(ExpandableBehavior expandableBehavior, View view, int i, com.google.android.material.expandable.a aVar) {
        this.d = expandableBehavior;
        this.a = view;
        this.b = i;
        this.c = aVar;
    }

    @Override // android.view.ViewTreeObserver.OnPreDrawListener
    public final boolean onPreDraw() {
        View view = this.a;
        view.getViewTreeObserver().removeOnPreDrawListener(this);
        ExpandableBehavior expandableBehavior = this.d;
        if (expandableBehavior.a == this.b) {
            Object obj = this.c;
            expandableBehavior.w((View) obj, view, ((FloatingActionButton) obj).o.b, false);
        }
        return false;
    }
}
