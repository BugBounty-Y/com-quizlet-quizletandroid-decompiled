package com.google.android.gms.internal.ads;

import android.view.View;

/* renamed from: com.google.android.gms.internal.ads.re, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class ViewOnAttachStateChangeListenerC2571re implements View.OnAttachStateChangeListener {
    public final /* synthetic */ InterfaceC1679Dc a;
    public final /* synthetic */ C1669Be b;

    public ViewOnAttachStateChangeListenerC2571re(C1669Be c1669Be, InterfaceC1679Dc interfaceC1679Dc) {
        this.a = interfaceC1679Dc;
        this.b = c1669Be;
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewAttachedToWindow(View view) {
        this.b.A(view, this.a, 10);
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewDetachedFromWindow(View view) {
    }
}
