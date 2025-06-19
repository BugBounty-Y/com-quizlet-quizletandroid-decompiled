package com.google.android.material.tabs;

import android.view.View;

/* loaded from: classes2.dex */
public final class i implements View.OnLayoutChangeListener {
    public final /* synthetic */ View a;
    public final /* synthetic */ j b;

    public i(j jVar, View view) {
        this.b = jVar;
        this.a = view;
    }

    @Override // android.view.View.OnLayoutChangeListener
    public final void onLayoutChange(View view, int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8) {
        View view2 = this.a;
        if (view2.getVisibility() == 0) {
            this.b.d(view2);
        }
    }
}
