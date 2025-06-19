package com.google.android.material.internal;

import android.view.View;
import androidx.core.view.J;
import androidx.core.view.V;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class r implements View.OnAttachStateChangeListener {
    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewAttachedToWindow(View view) {
        view.removeOnAttachStateChangeListener(this);
        WeakHashMap weakHashMap = V.a;
        J.c(view);
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewDetachedFromWindow(View view) {
    }
}
