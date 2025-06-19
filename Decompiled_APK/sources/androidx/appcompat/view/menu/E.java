package androidx.appcompat.view.menu;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Rect;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;
import android.widget.PopupWindow;
import android.widget.TextView;
import androidx.appcompat.widget.C0113u0;
import androidx.appcompat.widget.L0;
import com.quizlet.quizletandroid.R;

/* loaded from: classes.dex */
public final class E extends v implements PopupWindow.OnDismissListener, View.OnKeyListener {
    public final Context b;
    public final n c;
    public final k d;
    public final boolean e;
    public final int f;
    public final int g;
    public final L0 h;
    public final ViewTreeObserverOnGlobalLayoutListenerC0067d i;
    public final ViewOnAttachStateChangeListenerC0068e j;
    public w k;
    public View l;
    public View m;
    public y n;
    public ViewTreeObserver o;
    public boolean p;
    public boolean q;
    public int r;
    public int s = 0;
    public boolean t;

    public E(int i, Context context, View view, n nVar, boolean z) {
        int i2 = 1;
        this.i = new ViewTreeObserverOnGlobalLayoutListenerC0067d(this, i2);
        this.j = new ViewOnAttachStateChangeListenerC0068e(this, i2);
        this.b = context;
        this.c = nVar;
        this.e = z;
        this.d = new k(nVar, LayoutInflater.from(context), z, R.layout.abc_popup_menu_item_layout);
        this.g = i;
        Resources resources = context.getResources();
        this.f = Math.max(resources.getDisplayMetrics().widthPixels / 2, resources.getDimensionPixelSize(R.dimen.abc_config_prefDialogWidth));
        this.l = view;
        this.h = new L0(context, null, i);
        nVar.b(this, context);
    }

    @Override // androidx.appcompat.view.menu.D
    public final boolean a() {
        return !this.p && this.h.z.isShowing();
    }

    @Override // androidx.appcompat.view.menu.z
    public final boolean b() {
        return false;
    }

    @Override // androidx.appcompat.view.menu.z
    public final void c(y yVar) {
        this.n = yVar;
    }

    @Override // androidx.appcompat.view.menu.D
    public final void dismiss() {
        if (a()) {
            this.h.dismiss();
        }
    }

    @Override // androidx.appcompat.view.menu.z
    public final void e(n nVar, boolean z) {
        if (nVar != this.c) {
            return;
        }
        dismiss();
        y yVar = this.n;
        if (yVar != null) {
            yVar.e(nVar, z);
        }
    }

    @Override // androidx.appcompat.view.menu.D
    public final void f() {
        View view;
        if (a()) {
            return;
        }
        if (this.p || (view = this.l) == null) {
            throw new IllegalStateException("StandardMenuPopup cannot be used without an anchor");
        }
        this.m = view;
        L0 l0 = this.h;
        l0.z.setOnDismissListener(this);
        l0.p = this;
        l0.y = true;
        l0.z.setFocusable(true);
        View view2 = this.m;
        boolean z = this.o == null;
        ViewTreeObserver viewTreeObserver = view2.getViewTreeObserver();
        this.o = viewTreeObserver;
        if (z) {
            viewTreeObserver.addOnGlobalLayoutListener(this.i);
        }
        view2.addOnAttachStateChangeListener(this.j);
        l0.o = view2;
        l0.l = this.s;
        boolean z2 = this.q;
        Context context = this.b;
        k kVar = this.d;
        if (!z2) {
            this.r = v.m(kVar, context, this.f);
            this.q = true;
        }
        l0.r(this.r);
        l0.z.setInputMethodMode(2);
        Rect rect = this.a;
        l0.x = rect != null ? new Rect(rect) : null;
        l0.f();
        C0113u0 c0113u0 = l0.c;
        c0113u0.setOnKeyListener(this);
        if (this.t) {
            n nVar = this.c;
            if (nVar.m != null) {
                FrameLayout frameLayout = (FrameLayout) LayoutInflater.from(context).inflate(R.layout.abc_popup_menu_header_item_layout, (ViewGroup) c0113u0, false);
                TextView textView = (TextView) frameLayout.findViewById(android.R.id.title);
                if (textView != null) {
                    textView.setText(nVar.m);
                }
                frameLayout.setEnabled(false);
                c0113u0.addHeaderView(frameLayout, null, false);
            }
        }
        l0.p(kVar);
        l0.f();
    }

    @Override // androidx.appcompat.view.menu.z
    public final void h() {
        this.q = false;
        k kVar = this.d;
        if (kVar != null) {
            kVar.notifyDataSetChanged();
        }
    }

    @Override // androidx.appcompat.view.menu.D
    public final C0113u0 i() {
        return this.h.c;
    }

    @Override // androidx.appcompat.view.menu.z
    public final boolean j(F f) {
        if (f.hasVisibleItems()) {
            View view = this.m;
            x xVar = new x(this.g, this.b, view, f, this.e);
            y yVar = this.n;
            xVar.h = yVar;
            v vVar = xVar.i;
            if (vVar != null) {
                vVar.c(yVar);
            }
            boolean zU = v.u(f);
            xVar.g = zU;
            v vVar2 = xVar.i;
            if (vVar2 != null) {
                vVar2.o(zU);
            }
            xVar.j = this.k;
            this.k = null;
            this.c.c(false);
            L0 l0 = this.h;
            int width = l0.f;
            int iN = l0.n();
            if ((Gravity.getAbsoluteGravity(this.s, this.l.getLayoutDirection()) & 7) == 5) {
                width += this.l.getWidth();
            }
            if (!xVar.b()) {
                if (xVar.e != null) {
                    xVar.d(width, iN, true, true);
                }
            }
            y yVar2 = this.n;
            if (yVar2 != null) {
                yVar2.z(f);
            }
            return true;
        }
        return false;
    }

    @Override // androidx.appcompat.view.menu.v
    public final void l(n nVar) {
    }

    @Override // androidx.appcompat.view.menu.v
    public final void n(View view) {
        this.l = view;
    }

    @Override // androidx.appcompat.view.menu.v
    public final void o(boolean z) {
        this.d.c = z;
    }

    @Override // android.widget.PopupWindow.OnDismissListener
    public final void onDismiss() {
        this.p = true;
        this.c.c(true);
        ViewTreeObserver viewTreeObserver = this.o;
        if (viewTreeObserver != null) {
            if (!viewTreeObserver.isAlive()) {
                this.o = this.m.getViewTreeObserver();
            }
            this.o.removeGlobalOnLayoutListener(this.i);
            this.o = null;
        }
        this.m.removeOnAttachStateChangeListener(this.j);
        w wVar = this.k;
        if (wVar != null) {
            wVar.onDismiss();
        }
    }

    @Override // android.view.View.OnKeyListener
    public final boolean onKey(View view, int i, KeyEvent keyEvent) {
        if (keyEvent.getAction() != 1 || i != 82) {
            return false;
        }
        dismiss();
        return true;
    }

    @Override // androidx.appcompat.view.menu.v
    public final void p(int i) {
        this.s = i;
    }

    @Override // androidx.appcompat.view.menu.v
    public final void q(int i) {
        this.h.f = i;
    }

    @Override // androidx.appcompat.view.menu.v
    public final void r(PopupWindow.OnDismissListener onDismissListener) {
        this.k = (w) onDismissListener;
    }

    @Override // androidx.appcompat.view.menu.v
    public final void s(boolean z) {
        this.t = z;
    }

    @Override // androidx.appcompat.view.menu.v
    public final void t(int i) {
        this.h.k(i);
    }
}
