package androidx.fragment.app;

import android.view.View;
import android.view.ViewGroup;

/* loaded from: classes.dex */
public final class P implements View.OnAttachStateChangeListener {
    public final /* synthetic */ o0 a;
    public final /* synthetic */ Q b;

    public P(Q q, o0 o0Var) {
        this.b = q;
        this.a = o0Var;
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewAttachedToWindow(View view) {
        o0 o0Var = this.a;
        o0Var.i();
        C1147o.j((ViewGroup) o0Var.c.mView.getParent(), this.b.a).i();
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewDetachedFromWindow(View view) {
    }
}
