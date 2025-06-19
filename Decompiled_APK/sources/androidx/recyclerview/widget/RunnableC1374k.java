package androidx.recyclerview.widget;

import android.view.View;
import android.view.ViewPropertyAnimator;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/* renamed from: androidx.recyclerview.widget.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class RunnableC1374k implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ RunnableC1374k(int i, Object obj, Object obj2) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                ArrayList arrayList = (ArrayList) this.b;
                Iterator it2 = arrayList.iterator();
                while (true) {
                    boolean zHasNext = it2.hasNext();
                    C1386q c1386q = (C1386q) this.c;
                    if (!zHasNext) {
                        arrayList.clear();
                        c1386q.m.remove(arrayList);
                        break;
                    } else {
                        C1384p c1384p = (C1384p) it2.next();
                        F0 f0 = c1384p.a;
                        c1386q.getClass();
                        View view = f0.itemView;
                        int i = c1384p.d - c1384p.b;
                        int i2 = c1384p.e - c1384p.c;
                        if (i != 0) {
                            view.animate().translationX(DefinitionKt.NO_Float_VALUE);
                        }
                        if (i2 != 0) {
                            view.animate().translationY(DefinitionKt.NO_Float_VALUE);
                        }
                        ViewPropertyAnimator viewPropertyAnimatorAnimate = view.animate();
                        c1386q.p.add(f0);
                        viewPropertyAnimatorAnimate.setDuration(c1386q.e).setListener(new C1378m(c1386q, f0, i, view, i2, viewPropertyAnimatorAnimate)).start();
                    }
                }
            case 1:
                ArrayList arrayList2 = (ArrayList) this.b;
                Iterator it3 = arrayList2.iterator();
                while (true) {
                    boolean zHasNext2 = it3.hasNext();
                    C1386q c1386q2 = (C1386q) this.c;
                    if (!zHasNext2) {
                        arrayList2.clear();
                        c1386q2.n.remove(arrayList2);
                        break;
                    } else {
                        C1382o c1382o = (C1382o) it3.next();
                        c1386q2.getClass();
                        F0 f02 = c1382o.a;
                        View view2 = f02 == null ? null : f02.itemView;
                        F0 f03 = c1382o.b;
                        View view3 = f03 != null ? f03.itemView : null;
                        ArrayList arrayList3 = c1386q2.r;
                        if (view2 != null) {
                            ViewPropertyAnimator duration = view2.animate().setDuration(c1386q2.f);
                            arrayList3.add(c1382o.a);
                            duration.translationX(c1382o.e - c1382o.c);
                            duration.translationY(c1382o.f - c1382o.d);
                            duration.alpha(DefinitionKt.NO_Float_VALUE).setListener(new C1380n(c1386q2, c1382o, duration, view2, 0)).start();
                        }
                        if (view3 != null) {
                            ViewPropertyAnimator viewPropertyAnimatorAnimate2 = view3.animate();
                            arrayList3.add(c1382o.b);
                            viewPropertyAnimatorAnimate2.translationX(DefinitionKt.NO_Float_VALUE).translationY(DefinitionKt.NO_Float_VALUE).setDuration(c1386q2.f).alpha(1.0f).setListener(new C1380n(c1386q2, c1382o, viewPropertyAnimatorAnimate2, view3, 1)).start();
                        }
                    }
                }
            case 2:
                ArrayList arrayList4 = (ArrayList) this.b;
                Iterator it4 = arrayList4.iterator();
                while (true) {
                    boolean zHasNext3 = it4.hasNext();
                    C1386q c1386q3 = (C1386q) this.c;
                    if (!zHasNext3) {
                        arrayList4.clear();
                        c1386q3.l.remove(arrayList4);
                        break;
                    } else {
                        F0 f04 = (F0) it4.next();
                        c1386q3.getClass();
                        View view4 = f04.itemView;
                        ViewPropertyAnimator viewPropertyAnimatorAnimate3 = view4.animate();
                        c1386q3.o.add(f04);
                        viewPropertyAnimatorAnimate3.alpha(1.0f).setDuration(c1386q3.c).setListener(new C1376l(c1386q3, f04, view4, viewPropertyAnimatorAnimate3)).start();
                    }
                }
            default:
                androidx.fragment.app.y0 y0Var = (androidx.fragment.app.y0) this.c;
                C1364f c1364f = (C1364f) y0Var.f;
                if (c1364f.g == y0Var.b) {
                    List list = y0Var.d;
                    c1364f.e = list;
                    c1364f.f = Collections.unmodifiableList(list);
                    ((C1392u) this.b).a(c1364f.a);
                    c1364f.a((Runnable) y0Var.e);
                    break;
                }
                break;
        }
    }
}
