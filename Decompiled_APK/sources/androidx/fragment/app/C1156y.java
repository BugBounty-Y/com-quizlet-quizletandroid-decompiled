package androidx.fragment.app;

import android.view.View;

/* renamed from: androidx.fragment.app.y, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1156y implements androidx.lifecycle.H {
    public final /* synthetic */ Fragment a;

    public C1156y(Fragment fragment) {
        this.a = fragment;
    }

    @Override // androidx.lifecycle.H
    public final void d(androidx.lifecycle.J j, androidx.lifecycle.A a) {
        View view;
        if (a != androidx.lifecycle.A.ON_STOP || (view = this.a.mView) == null) {
            return;
        }
        view.cancelPendingInputEvents();
    }
}
