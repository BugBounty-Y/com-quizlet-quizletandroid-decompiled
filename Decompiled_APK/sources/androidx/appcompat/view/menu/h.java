package androidx.appcompat.view.menu;

import android.content.Context;
import android.content.res.Resources;
import android.os.Handler;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewTreeObserver;
import android.widget.HeaderViewListAdapter;
import android.widget.ListAdapter;
import android.widget.PopupWindow;
import androidx.appcompat.widget.C0113u0;
import androidx.appcompat.widget.I0;
import androidx.appcompat.widget.L0;
import com.quizlet.quizletandroid.R;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class h extends v implements View.OnKeyListener, PopupWindow.OnDismissListener {
    public final Context b;
    public final int c;
    public final int d;
    public final boolean e;
    public final Handler f;
    public final ViewTreeObserverOnGlobalLayoutListenerC0067d i;
    public final ViewOnAttachStateChangeListenerC0068e j;
    public View n;
    public View o;
    public int p;
    public boolean q;
    public boolean r;
    public int s;
    public int t;
    public boolean v;
    public y w;
    public ViewTreeObserver x;
    public w y;
    public boolean z;
    public final ArrayList g = new ArrayList();
    public final ArrayList h = new ArrayList();
    public final com.airbnb.lottie.network.c k = new com.airbnb.lottie.network.c(this, 2);
    public int l = 0;
    public int m = 0;
    public boolean u = false;

    public h(Context context, View view, int i, boolean z) {
        int i2 = 0;
        this.i = new ViewTreeObserverOnGlobalLayoutListenerC0067d(this, i2);
        this.j = new ViewOnAttachStateChangeListenerC0068e(this, i2);
        this.b = context;
        this.n = view;
        this.d = i;
        this.e = z;
        this.p = view.getLayoutDirection() != 1 ? 1 : 0;
        Resources resources = context.getResources();
        this.c = Math.max(resources.getDisplayMetrics().widthPixels / 2, resources.getDimensionPixelSize(R.dimen.abc_config_prefDialogWidth));
        this.f = new Handler();
    }

    @Override // androidx.appcompat.view.menu.D
    public final boolean a() {
        ArrayList arrayList = this.h;
        return arrayList.size() > 0 && ((g) arrayList.get(0)).a.z.isShowing();
    }

    @Override // androidx.appcompat.view.menu.z
    public final boolean b() {
        return false;
    }

    @Override // androidx.appcompat.view.menu.z
    public final void c(y yVar) {
        this.w = yVar;
    }

    @Override // androidx.appcompat.view.menu.D
    public final void dismiss() {
        ArrayList arrayList = this.h;
        int size = arrayList.size();
        if (size > 0) {
            g[] gVarArr = (g[]) arrayList.toArray(new g[size]);
            for (int i = size - 1; i >= 0; i--) {
                g gVar = gVarArr[i];
                if (gVar.a.z.isShowing()) {
                    gVar.a.dismiss();
                }
            }
        }
    }

    @Override // androidx.appcompat.view.menu.z
    public final void e(n nVar, boolean z) {
        ArrayList arrayList = this.h;
        int size = arrayList.size();
        int i = 0;
        while (true) {
            if (i >= size) {
                i = -1;
                break;
            } else if (nVar == ((g) arrayList.get(i)).b) {
                break;
            } else {
                i++;
            }
        }
        if (i < 0) {
            return;
        }
        int i2 = i + 1;
        if (i2 < arrayList.size()) {
            ((g) arrayList.get(i2)).b.c(false);
        }
        g gVar = (g) arrayList.remove(i);
        gVar.b.r(this);
        boolean z2 = this.z;
        L0 l0 = gVar.a;
        if (z2) {
            I0.b(l0.z, null);
            l0.z.setAnimationStyle(0);
        }
        l0.dismiss();
        int size2 = arrayList.size();
        if (size2 > 0) {
            this.p = ((g) arrayList.get(size2 - 1)).c;
        } else {
            this.p = this.n.getLayoutDirection() == 1 ? 0 : 1;
        }
        if (size2 != 0) {
            if (z) {
                ((g) arrayList.get(0)).b.c(false);
                return;
            }
            return;
        }
        dismiss();
        y yVar = this.w;
        if (yVar != null) {
            yVar.e(nVar, true);
        }
        ViewTreeObserver viewTreeObserver = this.x;
        if (viewTreeObserver != null) {
            if (viewTreeObserver.isAlive()) {
                this.x.removeGlobalOnLayoutListener(this.i);
            }
            this.x = null;
        }
        this.o.removeOnAttachStateChangeListener(this.j);
        this.y.onDismiss();
    }

    @Override // androidx.appcompat.view.menu.D
    public final void f() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        if (a()) {
            return;
        }
        ArrayList arrayList = this.g;
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            v((n) it2.next());
        }
        arrayList.clear();
        View view = this.n;
        this.o = view;
        if (view != null) {
            boolean z = this.x == null;
            ViewTreeObserver viewTreeObserver = view.getViewTreeObserver();
            this.x = viewTreeObserver;
            if (z) {
                viewTreeObserver.addOnGlobalLayoutListener(this.i);
            }
            this.o.addOnAttachStateChangeListener(this.j);
        }
    }

    @Override // androidx.appcompat.view.menu.z
    public final void h() {
        Iterator it2 = this.h.iterator();
        while (it2.hasNext()) {
            ListAdapter adapter = ((g) it2.next()).a.c.getAdapter();
            if (adapter instanceof HeaderViewListAdapter) {
                adapter = ((HeaderViewListAdapter) adapter).getWrappedAdapter();
            }
            ((k) adapter).notifyDataSetChanged();
        }
    }

    @Override // androidx.appcompat.view.menu.D
    public final C0113u0 i() {
        ArrayList arrayList = this.h;
        if (arrayList.isEmpty()) {
            return null;
        }
        return ((g) android.support.v4.media.session.a.e(1, arrayList)).a.c;
    }

    @Override // androidx.appcompat.view.menu.z
    public final boolean j(F f) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        Iterator it2 = this.h.iterator();
        while (it2.hasNext()) {
            g gVar = (g) it2.next();
            if (f == gVar.b) {
                gVar.a.c.requestFocus();
                return true;
            }
        }
        if (!f.hasVisibleItems()) {
            return false;
        }
        l(f);
        y yVar = this.w;
        if (yVar != null) {
            yVar.z(f);
        }
        return true;
    }

    @Override // androidx.appcompat.view.menu.v
    public final void l(n nVar) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        nVar.b(this, this.b);
        if (a()) {
            v(nVar);
        } else {
            this.g.add(nVar);
        }
    }

    @Override // androidx.appcompat.view.menu.v
    public final void n(View view) {
        if (this.n != view) {
            this.n = view;
            this.m = Gravity.getAbsoluteGravity(this.l, view.getLayoutDirection());
        }
    }

    @Override // androidx.appcompat.view.menu.v
    public final void o(boolean z) {
        this.u = z;
    }

    @Override // android.widget.PopupWindow.OnDismissListener
    public final void onDismiss() {
        g gVar;
        ArrayList arrayList = this.h;
        int size = arrayList.size();
        int i = 0;
        while (true) {
            if (i >= size) {
                gVar = null;
                break;
            }
            gVar = (g) arrayList.get(i);
            if (!gVar.a.z.isShowing()) {
                break;
            } else {
                i++;
            }
        }
        if (gVar != null) {
            gVar.b.c(false);
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
        if (this.l != i) {
            this.l = i;
            this.m = Gravity.getAbsoluteGravity(i, this.n.getLayoutDirection());
        }
    }

    @Override // androidx.appcompat.view.menu.v
    public final void q(int i) {
        this.q = true;
        this.s = i;
    }

    @Override // androidx.appcompat.view.menu.v
    public final void r(PopupWindow.OnDismissListener onDismissListener) {
        this.y = (w) onDismissListener;
    }

    @Override // androidx.appcompat.view.menu.v
    public final void s(boolean z) {
        this.v = z;
    }

    @Override // androidx.appcompat.view.menu.v
    public final void t(int i) {
        this.r = true;
        this.t = i;
    }

    /* JADX WARN: Removed duplicated region for block: B:46:0x00ea  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0143  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x0146  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x017c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void v(androidx.appcompat.view.menu.n r18) throws java.lang.IllegalAccessException, java.lang.IllegalArgumentException, java.lang.reflect.InvocationTargetException {
        /*
            Method dump skipped, instructions count: 472
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.view.menu.h.v(androidx.appcompat.view.menu.n):void");
    }
}
