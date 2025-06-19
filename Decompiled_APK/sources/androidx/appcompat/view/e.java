package androidx.appcompat.view;

import android.content.Context;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import androidx.appcompat.widget.ActionBarContextView;
import androidx.appcompat.widget.C0095l;
import androidx.compose.foundation.text.input.internal.u;
import java.lang.ref.WeakReference;

/* loaded from: classes.dex */
public final class e extends b implements androidx.appcompat.view.menu.l {
    public Context c;
    public ActionBarContextView d;
    public u e;
    public WeakReference f;
    public boolean g;
    public androidx.appcompat.view.menu.n h;

    @Override // androidx.appcompat.view.menu.l
    public final void D(androidx.appcompat.view.menu.n nVar) {
        g();
        C0095l c0095l = this.d.d;
        if (c0095l != null) {
            c0095l.l();
        }
    }

    @Override // androidx.appcompat.view.b
    public final void a() {
        if (this.g) {
            return;
        }
        this.g = true;
        this.e.l(this);
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
        return this.h;
    }

    @Override // androidx.appcompat.view.b
    public final MenuInflater d() {
        return new i(this.d.getContext());
    }

    @Override // androidx.appcompat.view.b
    public final CharSequence e() {
        return this.d.getSubtitle();
    }

    @Override // androidx.appcompat.view.b
    public final CharSequence f() {
        return this.d.getTitle();
    }

    @Override // androidx.appcompat.view.b
    public final void g() {
        this.e.m(this, this.h);
    }

    @Override // androidx.appcompat.view.b
    public final boolean h() {
        return this.d.s;
    }

    @Override // androidx.appcompat.view.b
    public final void i(View view) {
        this.d.setCustomView(view);
        this.f = view != null ? new WeakReference(view) : null;
    }

    @Override // androidx.appcompat.view.b
    public final void j(int i) {
        k(this.c.getString(i));
    }

    @Override // androidx.appcompat.view.b
    public final void k(CharSequence charSequence) {
        this.d.setSubtitle(charSequence);
    }

    @Override // androidx.appcompat.view.b
    public final void l(int i) {
        m(this.c.getString(i));
    }

    @Override // androidx.appcompat.view.b
    public final void m(CharSequence charSequence) {
        this.d.setTitle(charSequence);
    }

    @Override // androidx.appcompat.view.b
    public final void n(boolean z) {
        this.b = z;
        this.d.setTitleOptional(z);
    }

    @Override // androidx.appcompat.view.menu.l
    public final boolean r(androidx.appcompat.view.menu.n nVar, MenuItem menuItem) {
        return ((androidx.work.impl.model.i) this.e.b).h(this, menuItem);
    }
}
