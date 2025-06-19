package androidx.appcompat.widget;

import android.content.Context;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import com.comscore.streaming.ContentType;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class s1 implements androidx.appcompat.view.menu.z {
    public androidx.appcompat.view.menu.n a;
    public androidx.appcompat.view.menu.p b;
    public final /* synthetic */ Toolbar c;

    public s1(Toolbar toolbar) {
        this.c = toolbar;
    }

    @Override // androidx.appcompat.view.menu.z
    public final boolean b() {
        return false;
    }

    @Override // androidx.appcompat.view.menu.z
    public final boolean d(androidx.appcompat.view.menu.p pVar) {
        Toolbar toolbar = this.c;
        KeyEvent.Callback callback = toolbar.i;
        if (callback instanceof androidx.appcompat.view.c) {
            ((androidx.appcompat.view.c) callback).e();
        }
        toolbar.removeView(toolbar.i);
        toolbar.removeView(toolbar.h);
        toolbar.i = null;
        ArrayList arrayList = toolbar.E;
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            toolbar.addView((View) arrayList.get(size));
        }
        arrayList.clear();
        this.b = null;
        toolbar.requestLayout();
        pVar.C = false;
        pVar.n.p(false);
        toolbar.w();
        return true;
    }

    @Override // androidx.appcompat.view.menu.z
    public final void e(androidx.appcompat.view.menu.n nVar, boolean z) {
    }

    @Override // androidx.appcompat.view.menu.z
    public final void g(Context context, androidx.appcompat.view.menu.n nVar) {
        androidx.appcompat.view.menu.p pVar;
        androidx.appcompat.view.menu.n nVar2 = this.a;
        if (nVar2 != null && (pVar = this.b) != null) {
            nVar2.d(pVar);
        }
        this.a = nVar;
    }

    @Override // androidx.appcompat.view.menu.z
    public final void h() {
        if (this.b != null) {
            androidx.appcompat.view.menu.n nVar = this.a;
            if (nVar != null) {
                int size = nVar.f.size();
                for (int i = 0; i < size; i++) {
                    if (this.a.getItem(i) == this.b) {
                        return;
                    }
                }
            }
            d(this.b);
        }
    }

    @Override // androidx.appcompat.view.menu.z
    public final boolean j(androidx.appcompat.view.menu.F f) {
        return false;
    }

    @Override // androidx.appcompat.view.menu.z
    public final boolean k(androidx.appcompat.view.menu.p pVar) {
        Toolbar toolbar = this.c;
        toolbar.c();
        ViewParent parent = toolbar.h.getParent();
        if (parent != toolbar) {
            if (parent instanceof ViewGroup) {
                ((ViewGroup) parent).removeView(toolbar.h);
            }
            toolbar.addView(toolbar.h);
        }
        View actionView = pVar.getActionView();
        toolbar.i = actionView;
        this.b = pVar;
        ViewParent parent2 = actionView.getParent();
        if (parent2 != toolbar) {
            if (parent2 instanceof ViewGroup) {
                ((ViewGroup) parent2).removeView(toolbar.i);
            }
            t1 t1VarH = Toolbar.h();
            t1VarH.a = (toolbar.n & ContentType.LONG_FORM_ON_DEMAND) | 8388611;
            t1VarH.b = 2;
            toolbar.i.setLayoutParams(t1VarH);
            toolbar.addView(toolbar.i);
        }
        for (int childCount = toolbar.getChildCount() - 1; childCount >= 0; childCount--) {
            View childAt = toolbar.getChildAt(childCount);
            if (((t1) childAt.getLayoutParams()).b != 2 && childAt != toolbar.a) {
                toolbar.removeViewAt(childCount);
                toolbar.E.add(childAt);
            }
        }
        toolbar.requestLayout();
        pVar.C = true;
        pVar.n.p(false);
        KeyEvent.Callback callback = toolbar.i;
        if (callback instanceof androidx.appcompat.view.c) {
            ((androidx.appcompat.view.c) callback).c();
        }
        toolbar.w();
        return true;
    }
}
