package androidx.appcompat.app;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.Menu;
import androidx.appcompat.widget.ActionMenuView;
import androidx.appcompat.widget.C0095l;
import androidx.appcompat.widget.Toolbar;
import androidx.appcompat.widget.s1;
import androidx.appcompat.widget.x1;
import androidx.core.view.V;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class M extends com.bumptech.glide.c {
    public final x1 a;
    public final w b;
    public final com.quizlet.data.repository.school.membership.a c;
    public boolean d;
    public boolean e;
    public boolean f;
    public final ArrayList g = new ArrayList();
    public final J h = new J(this, 0);

    public M(Toolbar toolbar, CharSequence charSequence, w wVar) {
        com.google.firebase.platforminfo.c cVar = new com.google.firebase.platforminfo.c(this);
        toolbar.getClass();
        x1 x1Var = new x1(toolbar, false);
        this.a = x1Var;
        wVar.getClass();
        this.b = wVar;
        x1Var.k = wVar;
        toolbar.setOnMenuItemClickListener(cVar);
        if (!x1Var.g) {
            x1Var.h = charSequence;
            if ((x1Var.b & 8) != 0) {
                Toolbar toolbar2 = x1Var.a;
                toolbar2.setTitle(charSequence);
                if (x1Var.g) {
                    V.q(toolbar2.getRootView(), charSequence);
                }
            }
        }
        this.c = new com.quizlet.data.repository.school.membership.a(this, 1);
    }

    @Override // com.bumptech.glide.c
    public final void A(CharSequence charSequence) {
        x1 x1Var = this.a;
        x1Var.g = true;
        x1Var.h = charSequence;
        if ((x1Var.b & 8) != 0) {
            Toolbar toolbar = x1Var.a;
            toolbar.setTitle(charSequence);
            if (x1Var.g) {
                V.q(toolbar.getRootView(), charSequence);
            }
        }
    }

    @Override // com.bumptech.glide.c
    public final void B(CharSequence charSequence) {
        x1 x1Var = this.a;
        if (x1Var.g) {
            return;
        }
        x1Var.h = charSequence;
        if ((x1Var.b & 8) != 0) {
            Toolbar toolbar = x1Var.a;
            toolbar.setTitle(charSequence);
            if (x1Var.g) {
                V.q(toolbar.getRootView(), charSequence);
            }
        }
    }

    public final Menu F() {
        boolean z = this.e;
        x1 x1Var = this.a;
        if (!z) {
            K k = new K(this);
            L l = new L(this, 0);
            Toolbar toolbar = x1Var.a;
            toolbar.V = k;
            toolbar.W = l;
            ActionMenuView actionMenuView = toolbar.a;
            if (actionMenuView != null) {
                actionMenuView.u = k;
                actionMenuView.v = l;
            }
            this.e = true;
        }
        return x1Var.a.getMenu();
    }

    public final void G(int i, int i2) {
        x1 x1Var = this.a;
        x1Var.a((i & i2) | ((~i2) & x1Var.b));
    }

    @Override // com.bumptech.glide.c
    public final boolean f() {
        C0095l c0095l;
        ActionMenuView actionMenuView = this.a.a.a;
        return (actionMenuView == null || (c0095l = actionMenuView.t) == null || !c0095l.f()) ? false : true;
    }

    @Override // com.bumptech.glide.c
    public final boolean g() {
        androidx.appcompat.view.menu.p pVar;
        s1 s1Var = this.a.a.M;
        if (s1Var == null || (pVar = s1Var.b) == null) {
            return false;
        }
        if (s1Var == null) {
            pVar = null;
        }
        if (pVar == null) {
            return true;
        }
        pVar.collapseActionView();
        return true;
    }

    @Override // com.bumptech.glide.c
    public final void h(boolean z) {
        if (z == this.f) {
            return;
        }
        this.f = z;
        ArrayList arrayList = this.g;
        if (arrayList.size() <= 0) {
            return;
        }
        arrayList.get(0).getClass();
        throw new ClassCastException();
    }

    @Override // com.bumptech.glide.c
    public final int i() {
        return this.a.b;
    }

    @Override // com.bumptech.glide.c
    public final Context j() {
        return this.a.a.getContext();
    }

    @Override // com.bumptech.glide.c
    public final void k() {
        this.a.a.setVisibility(8);
    }

    @Override // com.bumptech.glide.c
    public final boolean l() {
        x1 x1Var = this.a;
        Toolbar toolbar = x1Var.a;
        J j = this.h;
        toolbar.removeCallbacks(j);
        Toolbar toolbar2 = x1Var.a;
        WeakHashMap weakHashMap = V.a;
        toolbar2.postOnAnimation(j);
        return true;
    }

    @Override // com.bumptech.glide.c
    public final void m() {
    }

    @Override // com.bumptech.glide.c
    public final void n() {
        this.a.a.removeCallbacks(this.h);
    }

    @Override // com.bumptech.glide.c
    public final boolean o(int i, KeyEvent keyEvent) {
        Menu menuF = F();
        if (menuF == null) {
            return false;
        }
        menuF.setQwertyMode(KeyCharacterMap.load(keyEvent.getDeviceId()).getKeyboardType() != 1);
        return menuF.performShortcut(i, keyEvent, 0);
    }

    @Override // com.bumptech.glide.c
    public final boolean p(KeyEvent keyEvent) {
        if (keyEvent.getAction() == 1) {
            q();
        }
        return true;
    }

    @Override // com.bumptech.glide.c
    public final boolean q() {
        return this.a.a.v();
    }

    @Override // com.bumptech.glide.c
    public final void r(boolean z) {
    }

    @Override // com.bumptech.glide.c
    public final void s(boolean z) {
        G(4, 4);
    }

    @Override // com.bumptech.glide.c
    public final void t() {
        G(2, 2);
    }

    @Override // com.bumptech.glide.c
    public final void u(boolean z) {
        G(z ? 8 : 0, 8);
    }

    @Override // com.bumptech.glide.c
    public final void v(Drawable drawable) {
        x1 x1Var = this.a;
        x1Var.f = drawable;
        int i = x1Var.b & 4;
        Toolbar toolbar = x1Var.a;
        if (i == 0) {
            toolbar.setNavigationIcon((Drawable) null);
            return;
        }
        if (drawable == null) {
            drawable = x1Var.o;
        }
        toolbar.setNavigationIcon(drawable);
    }

    @Override // com.bumptech.glide.c
    public final void w() {
    }

    @Override // com.bumptech.glide.c
    public final void x() {
        x1 x1Var = this.a;
        x1Var.e = null;
        x1Var.c();
    }

    @Override // com.bumptech.glide.c
    public final void y(boolean z) {
    }

    @Override // com.bumptech.glide.c
    public final void z() {
        x1 x1Var = this.a;
        CharSequence text = x1Var.a.getContext().getText(R.string.quizlet_live);
        x1Var.g = true;
        x1Var.h = text;
        if ((x1Var.b & 8) != 0) {
            Toolbar toolbar = x1Var.a;
            toolbar.setTitle(text);
            if (x1Var.g) {
                V.q(toolbar.getRootView(), text);
            }
        }
    }
}
