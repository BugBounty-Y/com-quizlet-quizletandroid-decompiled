package com.bumptech.glide.manager;

import android.view.View;
import android.view.ViewTreeObserver;

/* loaded from: classes.dex */
public final class d implements ViewTreeObserver.OnDrawListener {
    public final /* synthetic */ View a;
    public final /* synthetic */ e b;

    public d(e eVar, View view) {
        this.b = eVar;
        this.a = view;
    }

    @Override // android.view.ViewTreeObserver.OnDrawListener
    public final void onDraw() {
        com.bumptech.glide.util.m.f().post(new com.google.common.util.concurrent.d(this, false, this, 12));
    }
}
