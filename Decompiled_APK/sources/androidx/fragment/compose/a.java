package androidx.fragment.compose;

import androidx.fragment.app.Fragment;
import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import kotlin.jvm.internal.F;

/* loaded from: classes.dex */
public final class a implements InterfaceC1250k {
    public final /* synthetic */ F a;
    public final /* synthetic */ Fragment b;

    public a(F f, Fragment fragment) {
        this.a = f;
        this.b = fragment;
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onStart(J j) {
        this.a.a = false;
        this.b.getLifecycle().b(this);
    }
}
