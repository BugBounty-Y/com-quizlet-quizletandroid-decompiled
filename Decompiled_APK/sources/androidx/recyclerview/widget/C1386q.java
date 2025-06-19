package androidx.recyclerview.widget;

import android.animation.TimeInterpolator;
import android.animation.ValueAnimator;
import android.view.View;
import androidx.compose.material3.C0676l1;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* renamed from: androidx.recyclerview.widget.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1386q extends AbstractC1373j0 {
    public static TimeInterpolator s;
    public boolean g;
    public ArrayList h;
    public ArrayList i;
    public ArrayList j;
    public ArrayList k;
    public ArrayList l;
    public ArrayList m;
    public ArrayList n;
    public ArrayList o;
    public ArrayList p;
    public ArrayList q;
    public ArrayList r;

    public static void h(ArrayList arrayList) {
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            ((F0) arrayList.get(size)).itemView.animate().cancel();
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1373j0
    public final boolean a(F0 f0, F0 f02, C0676l1 c0676l1, C0676l1 c0676l12) {
        int i;
        int i2;
        int i3 = c0676l1.a;
        int i4 = c0676l1.b;
        if (f02.shouldIgnore()) {
            int i5 = c0676l1.a;
            i2 = c0676l1.b;
            i = i5;
        } else {
            i = c0676l12.a;
            i2 = c0676l12.b;
        }
        if (f0 == f02) {
            return g(f0, i3, i4, i, i2);
        }
        float translationX = f0.itemView.getTranslationX();
        float translationY = f0.itemView.getTranslationY();
        float alpha = f0.itemView.getAlpha();
        l(f0);
        f0.itemView.setTranslationX(translationX);
        f0.itemView.setTranslationY(translationY);
        f0.itemView.setAlpha(alpha);
        l(f02);
        f02.itemView.setTranslationX(-((int) ((i - i3) - translationX)));
        f02.itemView.setTranslationY(-((int) ((i2 - i4) - translationY)));
        f02.itemView.setAlpha(DefinitionKt.NO_Float_VALUE);
        ArrayList arrayList = this.k;
        C1382o c1382o = new C1382o();
        c1382o.a = f0;
        c1382o.b = f02;
        c1382o.c = i3;
        c1382o.d = i4;
        c1382o.e = i;
        c1382o.f = i2;
        arrayList.add(c1382o);
        return true;
    }

    @Override // androidx.recyclerview.widget.AbstractC1373j0
    public final void d(F0 f0) {
        View view = f0.itemView;
        view.animate().cancel();
        ArrayList arrayList = this.j;
        int size = arrayList.size();
        while (true) {
            size--;
            if (size < 0) {
                break;
            }
            if (((C1384p) arrayList.get(size)).a == f0) {
                view.setTranslationY(DefinitionKt.NO_Float_VALUE);
                view.setTranslationX(DefinitionKt.NO_Float_VALUE);
                c(f0);
                arrayList.remove(size);
            }
        }
        j(this.k, f0);
        if (this.h.remove(f0)) {
            view.setAlpha(1.0f);
            c(f0);
        }
        if (this.i.remove(f0)) {
            view.setAlpha(1.0f);
            c(f0);
        }
        ArrayList arrayList2 = this.n;
        for (int size2 = arrayList2.size() - 1; size2 >= 0; size2--) {
            ArrayList arrayList3 = (ArrayList) arrayList2.get(size2);
            j(arrayList3, f0);
            if (arrayList3.isEmpty()) {
                arrayList2.remove(size2);
            }
        }
        ArrayList arrayList4 = this.m;
        for (int size3 = arrayList4.size() - 1; size3 >= 0; size3--) {
            ArrayList arrayList5 = (ArrayList) arrayList4.get(size3);
            int size4 = arrayList5.size() - 1;
            while (true) {
                if (size4 < 0) {
                    break;
                }
                if (((C1384p) arrayList5.get(size4)).a == f0) {
                    view.setTranslationY(DefinitionKt.NO_Float_VALUE);
                    view.setTranslationX(DefinitionKt.NO_Float_VALUE);
                    c(f0);
                    arrayList5.remove(size4);
                    if (arrayList5.isEmpty()) {
                        arrayList4.remove(size3);
                    }
                } else {
                    size4--;
                }
            }
        }
        ArrayList arrayList6 = this.l;
        for (int size5 = arrayList6.size() - 1; size5 >= 0; size5--) {
            ArrayList arrayList7 = (ArrayList) arrayList6.get(size5);
            if (arrayList7.remove(f0)) {
                view.setAlpha(1.0f);
                c(f0);
                if (arrayList7.isEmpty()) {
                    arrayList6.remove(size5);
                }
            }
        }
        this.q.remove(f0);
        this.o.remove(f0);
        this.r.remove(f0);
        this.p.remove(f0);
        i();
    }

    @Override // androidx.recyclerview.widget.AbstractC1373j0
    public final void e() {
        ArrayList arrayList = this.j;
        int size = arrayList.size();
        while (true) {
            size--;
            if (size < 0) {
                break;
            }
            C1384p c1384p = (C1384p) arrayList.get(size);
            View view = c1384p.a.itemView;
            view.setTranslationY(DefinitionKt.NO_Float_VALUE);
            view.setTranslationX(DefinitionKt.NO_Float_VALUE);
            c(c1384p.a);
            arrayList.remove(size);
        }
        ArrayList arrayList2 = this.h;
        for (int size2 = arrayList2.size() - 1; size2 >= 0; size2--) {
            c((F0) arrayList2.get(size2));
            arrayList2.remove(size2);
        }
        ArrayList arrayList3 = this.i;
        int size3 = arrayList3.size();
        while (true) {
            size3--;
            if (size3 < 0) {
                break;
            }
            F0 f0 = (F0) arrayList3.get(size3);
            f0.itemView.setAlpha(1.0f);
            c(f0);
            arrayList3.remove(size3);
        }
        ArrayList arrayList4 = this.k;
        for (int size4 = arrayList4.size() - 1; size4 >= 0; size4--) {
            C1382o c1382o = (C1382o) arrayList4.get(size4);
            F0 f02 = c1382o.a;
            if (f02 != null) {
                k(c1382o, f02);
            }
            F0 f03 = c1382o.b;
            if (f03 != null) {
                k(c1382o, f03);
            }
        }
        arrayList4.clear();
        if (f()) {
            ArrayList arrayList5 = this.m;
            for (int size5 = arrayList5.size() - 1; size5 >= 0; size5--) {
                ArrayList arrayList6 = (ArrayList) arrayList5.get(size5);
                for (int size6 = arrayList6.size() - 1; size6 >= 0; size6--) {
                    C1384p c1384p2 = (C1384p) arrayList6.get(size6);
                    View view2 = c1384p2.a.itemView;
                    view2.setTranslationY(DefinitionKt.NO_Float_VALUE);
                    view2.setTranslationX(DefinitionKt.NO_Float_VALUE);
                    c(c1384p2.a);
                    arrayList6.remove(size6);
                    if (arrayList6.isEmpty()) {
                        arrayList5.remove(arrayList6);
                    }
                }
            }
            ArrayList arrayList7 = this.l;
            for (int size7 = arrayList7.size() - 1; size7 >= 0; size7--) {
                ArrayList arrayList8 = (ArrayList) arrayList7.get(size7);
                for (int size8 = arrayList8.size() - 1; size8 >= 0; size8--) {
                    F0 f04 = (F0) arrayList8.get(size8);
                    f04.itemView.setAlpha(1.0f);
                    c(f04);
                    arrayList8.remove(size8);
                    if (arrayList8.isEmpty()) {
                        arrayList7.remove(arrayList8);
                    }
                }
            }
            ArrayList arrayList9 = this.n;
            for (int size9 = arrayList9.size() - 1; size9 >= 0; size9--) {
                ArrayList arrayList10 = (ArrayList) arrayList9.get(size9);
                for (int size10 = arrayList10.size() - 1; size10 >= 0; size10--) {
                    C1382o c1382o2 = (C1382o) arrayList10.get(size10);
                    F0 f05 = c1382o2.a;
                    if (f05 != null) {
                        k(c1382o2, f05);
                    }
                    F0 f06 = c1382o2.b;
                    if (f06 != null) {
                        k(c1382o2, f06);
                    }
                    if (arrayList10.isEmpty()) {
                        arrayList9.remove(arrayList10);
                    }
                }
            }
            h(this.q);
            h(this.p);
            h(this.o);
            h(this.r);
            ArrayList arrayList11 = this.b;
            if (arrayList11.size() > 0) {
                arrayList11.get(0).getClass();
                throw new ClassCastException();
            }
            arrayList11.clear();
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1373j0
    public final boolean f() {
        return (this.i.isEmpty() && this.k.isEmpty() && this.j.isEmpty() && this.h.isEmpty() && this.p.isEmpty() && this.q.isEmpty() && this.o.isEmpty() && this.r.isEmpty() && this.m.isEmpty() && this.l.isEmpty() && this.n.isEmpty()) ? false : true;
    }

    public final boolean g(F0 f0, int i, int i2, int i3, int i4) {
        View view = f0.itemView;
        int translationX = i + ((int) view.getTranslationX());
        int translationY = i2 + ((int) f0.itemView.getTranslationY());
        l(f0);
        int i5 = i3 - translationX;
        int i6 = i4 - translationY;
        if (i5 == 0 && i6 == 0) {
            c(f0);
            return false;
        }
        if (i5 != 0) {
            view.setTranslationX(-i5);
        }
        if (i6 != 0) {
            view.setTranslationY(-i6);
        }
        ArrayList arrayList = this.j;
        C1384p c1384p = new C1384p();
        c1384p.a = f0;
        c1384p.b = translationX;
        c1384p.c = translationY;
        c1384p.d = i3;
        c1384p.e = i4;
        arrayList.add(c1384p);
        return true;
    }

    public final void i() {
        if (f()) {
            return;
        }
        ArrayList arrayList = this.b;
        if (arrayList.size() <= 0) {
            arrayList.clear();
        } else {
            arrayList.get(0).getClass();
            throw new ClassCastException();
        }
    }

    public final void j(ArrayList arrayList, F0 f0) {
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            C1382o c1382o = (C1382o) arrayList.get(size);
            if (k(c1382o, f0) && c1382o.a == null && c1382o.b == null) {
                arrayList.remove(c1382o);
            }
        }
    }

    public final boolean k(C1382o c1382o, F0 f0) {
        if (c1382o.b == f0) {
            c1382o.b = null;
        } else {
            if (c1382o.a != f0) {
                return false;
            }
            c1382o.a = null;
        }
        f0.itemView.setAlpha(1.0f);
        f0.itemView.setTranslationX(DefinitionKt.NO_Float_VALUE);
        f0.itemView.setTranslationY(DefinitionKt.NO_Float_VALUE);
        c(f0);
        return true;
    }

    public final void l(F0 f0) {
        if (s == null) {
            s = new ValueAnimator().getInterpolator();
        }
        f0.itemView.animate().setInterpolator(s);
        d(f0);
    }
}
