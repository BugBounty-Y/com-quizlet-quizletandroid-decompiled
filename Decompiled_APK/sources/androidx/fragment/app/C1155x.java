package androidx.fragment.app;

import android.view.View;

/* renamed from: androidx.fragment.app.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1155x extends L {
    public final /* synthetic */ Fragment a;

    public C1155x(Fragment fragment) {
        this.a = fragment;
    }

    @Override // androidx.fragment.app.L
    public final View b(int i) {
        Fragment fragment = this.a;
        View view = fragment.mView;
        if (view != null) {
            return view.findViewById(i);
        }
        throw new IllegalStateException("Fragment " + fragment + " does not have a view");
    }

    @Override // androidx.fragment.app.L
    public final boolean c() {
        return this.a.mView != null;
    }
}
