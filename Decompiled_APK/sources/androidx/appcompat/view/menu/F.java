package androidx.appcompat.view.menu;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.view.MenuItem;
import android.view.SubMenu;
import android.view.View;

/* loaded from: classes.dex */
public final class F extends n implements SubMenu {
    public final p A;
    public final n z;

    public F(Context context, n nVar, p pVar) {
        super(context);
        this.z = nVar;
        this.A = pVar;
    }

    @Override // androidx.appcompat.view.menu.n
    public final boolean d(p pVar) {
        return this.z.d(pVar);
    }

    @Override // androidx.appcompat.view.menu.n
    public final boolean e(n nVar, MenuItem menuItem) {
        return super.e(nVar, menuItem) || this.z.e(nVar, menuItem);
    }

    @Override // androidx.appcompat.view.menu.n
    public final boolean f(p pVar) {
        return this.z.f(pVar);
    }

    @Override // android.view.SubMenu
    public final MenuItem getItem() {
        return this.A;
    }

    @Override // androidx.appcompat.view.menu.n
    public final String j() {
        p pVar = this.A;
        int i = pVar != null ? pVar.a : 0;
        if (i == 0) {
            return null;
        }
        return android.support.v4.media.session.a.f(i, "android:menu:actionviewstates:");
    }

    @Override // androidx.appcompat.view.menu.n
    public final n k() {
        return this.z.k();
    }

    @Override // androidx.appcompat.view.menu.n
    public final boolean m() {
        return this.z.m();
    }

    @Override // androidx.appcompat.view.menu.n
    public final boolean n() {
        return this.z.n();
    }

    @Override // androidx.appcompat.view.menu.n
    public final boolean o() {
        return this.z.o();
    }

    @Override // androidx.appcompat.view.menu.n, android.view.Menu
    public final void setGroupDividerEnabled(boolean z) {
        this.z.setGroupDividerEnabled(z);
    }

    @Override // android.view.SubMenu
    public final SubMenu setHeaderIcon(Drawable drawable) {
        u(0, null, 0, drawable, null);
        return this;
    }

    @Override // android.view.SubMenu
    public final SubMenu setHeaderTitle(CharSequence charSequence) {
        u(0, charSequence, 0, null, null);
        return this;
    }

    @Override // android.view.SubMenu
    public final SubMenu setHeaderView(View view) {
        u(0, null, 0, null, view);
        return this;
    }

    @Override // android.view.SubMenu
    public final SubMenu setIcon(Drawable drawable) {
        this.A.setIcon(drawable);
        return this;
    }

    @Override // androidx.appcompat.view.menu.n, android.view.Menu
    public final void setQwertyMode(boolean z) {
        this.z.setQwertyMode(z);
    }

    @Override // android.view.SubMenu
    public final SubMenu setHeaderIcon(int i) {
        u(0, null, i, null, null);
        return this;
    }

    @Override // android.view.SubMenu
    public final SubMenu setHeaderTitle(int i) {
        u(i, null, 0, null, null);
        return this;
    }

    @Override // android.view.SubMenu
    public final SubMenu setIcon(int i) {
        this.A.setIcon(i);
        return this;
    }
}
