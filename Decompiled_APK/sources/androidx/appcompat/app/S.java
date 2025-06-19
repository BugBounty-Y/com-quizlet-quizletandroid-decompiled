package androidx.appcompat.app;

import android.content.Context;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import androidx.appcompat.widget.ActionBarContextView;
import androidx.appcompat.widget.C0095l;
import java.lang.ref.WeakReference;

/* loaded from: classes.dex */
public final class S extends androidx.appcompat.view.b implements androidx.appcompat.view.menu.l {
    public final Context c;
    public final androidx.appcompat.view.menu.n d;
    public androidx.compose.foundation.text.input.internal.u e;
    public WeakReference f;
    public final /* synthetic */ T g;

    public S(T t, Context context, androidx.compose.foundation.text.input.internal.u uVar) {
        this.g = t;
        this.c = context;
        this.e = uVar;
        androidx.appcompat.view.menu.n nVar = new androidx.appcompat.view.menu.n(context);
        nVar.l = 1;
        this.d = nVar;
        nVar.e = this;
    }

    @Override // androidx.appcompat.view.menu.l
    public final void D(androidx.appcompat.view.menu.n nVar) {
        if (this.e == null) {
            return;
        }
        g();
        C0095l c0095l = this.g.f.d;
        if (c0095l != null) {
            c0095l.l();
        }
    }

    @Override // androidx.appcompat.view.b
    public final void a() {
        T t = this.g;
        if (t.i != this) {
            return;
        }
        boolean z = t.p;
        boolean z2 = t.q;
        if (z || z2) {
            t.j = this;
            t.k = this.e;
        } else {
            this.e.l(this);
        }
        this.e = null;
        t.F(false);
        ActionBarContextView actionBarContextView = t.f;
        if (actionBarContextView.k == null) {
            actionBarContextView.e();
        }
        t.c.setHideOnContentScrollEnabled(t.v);
        t.i = null;
    }

    @Override // androidx.appcompat.view.b
    public final View b() {
        WeakReference weakReference = this.f;
        if (weakReference != null) {
            return (View) weakReference.get();
        }
        return null;
    }

    @Override // androidx.appcompat.view.b
    public final androidx.appcompat.view.menu.n c() {
        return this.d;
    }

    @Override // androidx.appcompat.view.b
    public final MenuInflater d() {
        return new androidx.appcompat.view.i(this.c);
    }

    @Override // androidx.appcompat.view.b
    public final CharSequence e() {
        return this.g.f.getSubtitle();
    }

    @Override // androidx.appcompat.view.b
    public final CharSequence f() {
        return this.g.f.getTitle();
    }

    @Override // androidx.appcompat.view.b
    public final void g() {
        if (this.g.i != this) {
            return;
        }
        androidx.appcompat.view.menu.n nVar = this.d;
        nVar.w();
        try {
            this.e.m(this, nVar);
        } finally {
            nVar.v();
        }
    }

    @Override // androidx.appcompat.view.b
    public final boolean h() {
        return this.g.f.s;
    }

    @Override // androidx.appcompat.view.b
    public final void i(View view) {
        this.g.f.setCustomView(view);
        this.f = new WeakReference(view);
    }

    @Override // androidx.appcompat.view.b
    public final void j(int i) {
        k(this.g.a.getResources().getString(i));
    }

    @Override // androidx.appcompat.view.b
    public final void k(CharSequence charSequence) {
        this.g.f.setSubtitle(charSequence);
    }

    @Override // androidx.appcompat.view.b
    public final void l(int i) {
        m(this.g.a.getResources().getString(i));
    }

    @Override // androidx.appcompat.view.b
    public final void m(CharSequence charSequence) {
        this.g.f.setTitle(charSequence);
    }

    @Override // androidx.appcompat.view.b
    public final void n(boolean z) {
        this.b = z;
        this.g.f.setTitleOptional(z);
    }

    @Override // androidx.appcompat.view.menu.l
    public final boolean r(androidx.appcompat.view.menu.n nVar, MenuItem menuItem) {
        androidx.compose.foundation.text.input.internal.u uVar = this.e;
        if (uVar != null) {
            return ((androidx.work.impl.model.i) uVar.b).h(this, menuItem);
        }
        return false;
    }
}
