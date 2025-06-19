package androidx.fragment.app;

import android.os.Bundle;

/* renamed from: androidx.fragment.app.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1154w extends C {
    public final /* synthetic */ Fragment a;

    public C1154w(Fragment fragment) {
        this.a = fragment;
    }

    @Override // androidx.fragment.app.C
    public final void a() {
        Fragment fragment = this.a;
        fragment.mSavedStateRegistryController.a.d();
        androidx.lifecycle.p0.d(fragment);
        Bundle bundle = fragment.mSavedFragmentState;
        fragment.mSavedStateRegistryController.a(bundle != null ? bundle.getBundle("registryState") : null);
    }
}
