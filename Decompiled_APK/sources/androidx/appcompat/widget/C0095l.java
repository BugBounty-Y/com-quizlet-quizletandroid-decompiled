package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.util.SparseBooleanArray;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import androidx.appcompat.view.menu.ActionMenuItemView;
import androidx.core.view.AbstractC1040c;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;

/* renamed from: androidx.appcompat.widget.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C0095l implements androidx.appcompat.view.menu.z {
    public final Context a;
    public Context b;
    public androidx.appcompat.view.menu.n c;
    public final LayoutInflater d;
    public androidx.appcompat.view.menu.y e;
    public androidx.appcompat.view.menu.B h;
    public C0093k i;
    public Drawable j;
    public boolean k;
    public boolean l;
    public boolean m;
    public int n;
    public int o;
    public int p;
    public boolean q;
    public C0087h s;
    public C0087h t;
    public RunnableC0091j u;
    public C0089i v;
    public final int f = R.layout.abc_action_menu_layout;
    public final int g = R.layout.abc_action_menu_item_layout;
    public final SparseBooleanArray r = new SparseBooleanArray();
    public final com.google.android.gms.auth.api.signin.internal.h w = new com.google.android.gms.auth.api.signin.internal.h(this, 2);

    public C0095l(Context context) {
        this.a = context;
        this.d = LayoutInflater.from(context);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r5v0, types: [android.view.View] */
    /* JADX WARN: Type inference failed for: r5v4, types: [androidx.appcompat.view.menu.A] */
    /* JADX WARN: Type inference failed for: r5v7 */
    /* JADX WARN: Type inference failed for: r5v8 */
    public final View a(androidx.appcompat.view.menu.p pVar, View view, ViewGroup viewGroup) {
        View actionView = pVar.getActionView();
        if (actionView == null || pVar.e()) {
            ActionMenuItemView actionMenuItemView = view instanceof androidx.appcompat.view.menu.A ? (androidx.appcompat.view.menu.A) view : (androidx.appcompat.view.menu.A) this.d.inflate(this.g, viewGroup, false);
            actionMenuItemView.d(pVar);
            ActionMenuItemView actionMenuItemView2 = actionMenuItemView;
            actionMenuItemView2.setItemInvoker((ActionMenuView) this.h);
            if (this.v == null) {
                this.v = new C0089i(this);
            }
            actionMenuItemView2.setPopupCallback(this.v);
            actionView = actionMenuItemView;
        }
        actionView.setVisibility(pVar.C ? 8 : 0);
        ViewGroup.LayoutParams layoutParams = actionView.getLayoutParams();
        ((ActionMenuView) viewGroup).getClass();
        if (!(layoutParams instanceof C0099n)) {
            actionView.setLayoutParams(ActionMenuView.m(layoutParams));
        }
        return actionView;
    }

    @Override // androidx.appcompat.view.menu.z
    public final boolean b() {
        int size;
        ArrayList arrayListL;
        int i;
        boolean z;
        C0095l c0095l = this;
        androidx.appcompat.view.menu.n nVar = c0095l.c;
        if (nVar != null) {
            arrayListL = nVar.l();
            size = arrayListL.size();
        } else {
            size = 0;
            arrayListL = null;
        }
        int i2 = c0095l.p;
        int i3 = c0095l.o;
        int iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(0, 0);
        ViewGroup viewGroup = (ViewGroup) c0095l.h;
        int i4 = 0;
        boolean z2 = false;
        int i5 = 0;
        int i6 = 0;
        while (true) {
            i = 2;
            z = true;
            if (i4 >= size) {
                break;
            }
            androidx.appcompat.view.menu.p pVar = (androidx.appcompat.view.menu.p) arrayListL.get(i4);
            int i7 = pVar.y;
            if ((i7 & 2) == 2) {
                i5++;
            } else if ((i7 & 1) == 1) {
                i6++;
            } else {
                z2 = true;
            }
            if (c0095l.q && pVar.C) {
                i2 = 0;
            }
            i4++;
        }
        if (c0095l.l && (z2 || i6 + i5 > i2)) {
            i2--;
        }
        int i8 = i2 - i5;
        SparseBooleanArray sparseBooleanArray = c0095l.r;
        sparseBooleanArray.clear();
        int i9 = 0;
        int i10 = 0;
        while (i9 < size) {
            androidx.appcompat.view.menu.p pVar2 = (androidx.appcompat.view.menu.p) arrayListL.get(i9);
            int i11 = pVar2.y;
            boolean z3 = (i11 & 2) == i ? z : false;
            int i12 = pVar2.b;
            if (z3) {
                View viewA = c0095l.a(pVar2, null, viewGroup);
                viewA.measure(iMakeMeasureSpec, iMakeMeasureSpec);
                int measuredWidth = viewA.getMeasuredWidth();
                i3 -= measuredWidth;
                if (i10 == 0) {
                    i10 = measuredWidth;
                }
                if (i12 != 0) {
                    sparseBooleanArray.put(i12, z);
                }
                pVar2.f(z);
            } else if ((i11 & 1) == z) {
                boolean z4 = sparseBooleanArray.get(i12);
                boolean z5 = ((i8 > 0 || z4) && i3 > 0) ? z : false;
                if (z5) {
                    View viewA2 = c0095l.a(pVar2, null, viewGroup);
                    viewA2.measure(iMakeMeasureSpec, iMakeMeasureSpec);
                    int measuredWidth2 = viewA2.getMeasuredWidth();
                    i3 -= measuredWidth2;
                    if (i10 == 0) {
                        i10 = measuredWidth2;
                    }
                    z5 &= i3 + i10 > 0;
                }
                if (z5 && i12 != 0) {
                    sparseBooleanArray.put(i12, true);
                } else if (z4) {
                    sparseBooleanArray.put(i12, false);
                    for (int i13 = 0; i13 < i9; i13++) {
                        androidx.appcompat.view.menu.p pVar3 = (androidx.appcompat.view.menu.p) arrayListL.get(i13);
                        if (pVar3.b == i12) {
                            if ((pVar3.x & 32) == 32) {
                                i8++;
                            }
                            pVar3.f(false);
                        }
                    }
                }
                if (z5) {
                    i8--;
                }
                pVar2.f(z5);
            } else {
                pVar2.f(false);
                i9++;
                i = 2;
                c0095l = this;
                z = true;
            }
            i9++;
            i = 2;
            c0095l = this;
            z = true;
        }
        return z;
    }

    @Override // androidx.appcompat.view.menu.z
    public final void c(androidx.appcompat.view.menu.y yVar) {
        throw null;
    }

    @Override // androidx.appcompat.view.menu.z
    public final boolean d(androidx.appcompat.view.menu.p pVar) {
        return false;
    }

    @Override // androidx.appcompat.view.menu.z
    public final void e(androidx.appcompat.view.menu.n nVar, boolean z) {
        f();
        C0087h c0087h = this.t;
        if (c0087h != null && c0087h.b()) {
            c0087h.i.dismiss();
        }
        androidx.appcompat.view.menu.y yVar = this.e;
        if (yVar != null) {
            yVar.e(nVar, z);
        }
    }

    public final boolean f() {
        Object obj;
        RunnableC0091j runnableC0091j = this.u;
        if (runnableC0091j != null && (obj = this.h) != null) {
            ((View) obj).removeCallbacks(runnableC0091j);
            this.u = null;
            return true;
        }
        C0087h c0087h = this.s;
        if (c0087h == null) {
            return false;
        }
        if (c0087h.b()) {
            c0087h.i.dismiss();
        }
        return true;
    }

    @Override // androidx.appcompat.view.menu.z
    public final void g(Context context, androidx.appcompat.view.menu.n nVar) {
        this.b = context;
        LayoutInflater.from(context);
        this.c = nVar;
        Resources resources = context.getResources();
        androidx.appcompat.view.a aVarA = androidx.appcompat.view.a.a(context);
        if (!this.m) {
            this.l = true;
        }
        this.n = aVarA.a.getResources().getDisplayMetrics().widthPixels / 2;
        this.p = aVarA.d();
        int measuredWidth = this.n;
        if (this.l) {
            if (this.i == null) {
                C0093k c0093k = new C0093k(this, this.a);
                this.i = c0093k;
                if (this.k) {
                    c0093k.setImageDrawable(this.j);
                    this.j = null;
                    this.k = false;
                }
                int iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(0, 0);
                this.i.measure(iMakeMeasureSpec, iMakeMeasureSpec);
            }
            measuredWidth -= this.i.getMeasuredWidth();
        } else {
            this.i = null;
        }
        this.o = measuredWidth;
        float f = resources.getDisplayMetrics().density;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // androidx.appcompat.view.menu.z
    public final void h() {
        int i;
        ViewGroup viewGroup = (ViewGroup) this.h;
        ArrayList arrayList = null;
        boolean z = false;
        if (viewGroup != null) {
            androidx.appcompat.view.menu.n nVar = this.c;
            if (nVar != null) {
                nVar.i();
                ArrayList arrayListL = this.c.l();
                int size = arrayListL.size();
                i = 0;
                for (int i2 = 0; i2 < size; i2++) {
                    androidx.appcompat.view.menu.p pVar = (androidx.appcompat.view.menu.p) arrayListL.get(i2);
                    if ((pVar.x & 32) == 32) {
                        View childAt = viewGroup.getChildAt(i);
                        androidx.appcompat.view.menu.p itemData = childAt instanceof androidx.appcompat.view.menu.A ? ((androidx.appcompat.view.menu.A) childAt).getItemData() : null;
                        View viewA = a(pVar, childAt, viewGroup);
                        if (pVar != itemData) {
                            viewA.setPressed(false);
                            viewA.jumpDrawablesToCurrentState();
                        }
                        if (viewA != childAt) {
                            ViewGroup viewGroup2 = (ViewGroup) viewA.getParent();
                            if (viewGroup2 != null) {
                                viewGroup2.removeView(viewA);
                            }
                            ((ViewGroup) this.h).addView(viewA, i);
                        }
                        i++;
                    }
                }
            } else {
                i = 0;
            }
            while (i < viewGroup.getChildCount()) {
                if (viewGroup.getChildAt(i) == this.i) {
                    i++;
                } else {
                    viewGroup.removeViewAt(i);
                }
            }
        }
        ((View) this.h).requestLayout();
        androidx.appcompat.view.menu.n nVar2 = this.c;
        if (nVar2 != null) {
            nVar2.i();
            ArrayList arrayList2 = nVar2.i;
            int size2 = arrayList2.size();
            for (int i3 = 0; i3 < size2; i3++) {
                AbstractC1040c abstractC1040c = ((androidx.appcompat.view.menu.p) arrayList2.get(i3)).A;
            }
        }
        androidx.appcompat.view.menu.n nVar3 = this.c;
        if (nVar3 != null) {
            nVar3.i();
            arrayList = nVar3.j;
        }
        if (this.l && arrayList != null) {
            int size3 = arrayList.size();
            if (size3 == 1) {
                z = !((androidx.appcompat.view.menu.p) arrayList.get(0)).C;
            } else if (size3 > 0) {
                z = true;
            }
        }
        if (z) {
            if (this.i == null) {
                this.i = new C0093k(this, this.a);
            }
            ViewGroup viewGroup3 = (ViewGroup) this.i.getParent();
            if (viewGroup3 != this.h) {
                if (viewGroup3 != null) {
                    viewGroup3.removeView(this.i);
                }
                ActionMenuView actionMenuView = (ActionMenuView) this.h;
                C0093k c0093k = this.i;
                actionMenuView.getClass();
                C0099n c0099nL = ActionMenuView.l();
                c0099nL.a = true;
                actionMenuView.addView(c0093k, c0099nL);
            }
        } else {
            C0093k c0093k2 = this.i;
            if (c0093k2 != null) {
                Object parent = c0093k2.getParent();
                Object obj = this.h;
                if (parent == obj) {
                    ((ViewGroup) obj).removeView(this.i);
                }
            }
        }
        ((ActionMenuView) this.h).setOverflowReserved(this.l);
    }

    public final boolean i() {
        C0087h c0087h = this.s;
        return c0087h != null && c0087h.b();
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // androidx.appcompat.view.menu.z
    public final boolean j(androidx.appcompat.view.menu.F f) {
        boolean z;
        if (f.hasVisibleItems()) {
            androidx.appcompat.view.menu.F f2 = f;
            while (true) {
                androidx.appcompat.view.menu.n nVar = f2.z;
                if (nVar == this.c) {
                    break;
                }
                f2 = (androidx.appcompat.view.menu.F) nVar;
            }
            ViewGroup viewGroup = (ViewGroup) this.h;
            View view = null;
            if (viewGroup != null) {
                int childCount = viewGroup.getChildCount();
                int i = 0;
                while (true) {
                    if (i >= childCount) {
                        break;
                    }
                    View childAt = viewGroup.getChildAt(i);
                    if ((childAt instanceof androidx.appcompat.view.menu.A) && ((androidx.appcompat.view.menu.A) childAt).getItemData() == f2.A) {
                        view = childAt;
                        break;
                    }
                    i++;
                }
            }
            if (view != null) {
                f.A.getClass();
                int size = f.f.size();
                int i2 = 0;
                while (true) {
                    if (i2 >= size) {
                        z = false;
                        break;
                    }
                    MenuItem item = f.getItem(i2);
                    if (item.isVisible() && item.getIcon() != null) {
                        z = true;
                        break;
                    }
                    i2++;
                }
                C0087h c0087h = new C0087h(this, this.b, f, view);
                this.t = c0087h;
                c0087h.g = z;
                androidx.appcompat.view.menu.v vVar = c0087h.i;
                if (vVar != null) {
                    vVar.o(z);
                }
                C0087h c0087h2 = this.t;
                if (!c0087h2.b()) {
                    if (c0087h2.e == null) {
                        throw new IllegalStateException("MenuPopupHelper cannot be used without an anchor");
                    }
                    c0087h2.d(0, 0, false, false);
                }
                androidx.appcompat.view.menu.y yVar = this.e;
                if (yVar != null) {
                    yVar.z(f);
                }
                return true;
            }
        }
        return false;
    }

    @Override // androidx.appcompat.view.menu.z
    public final boolean k(androidx.appcompat.view.menu.p pVar) {
        return false;
    }

    public final boolean l() {
        androidx.appcompat.view.menu.n nVar;
        if (!this.l || i() || (nVar = this.c) == null || this.h == null || this.u != null) {
            return false;
        }
        nVar.i();
        if (nVar.j.isEmpty()) {
            return false;
        }
        RunnableC0091j runnableC0091j = new RunnableC0091j(0, this, new C0087h(this, this.b, this.c, this.i));
        this.u = runnableC0091j;
        ((View) this.h).post(runnableC0091j);
        return true;
    }
}
