package androidx.fragment.app;

import android.graphics.Rect;
import android.os.Build;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import androidx.activity.C0030b;
import androidx.camera.camera2.internal.RunnableC0130g;
import androidx.collection.C0208f;
import androidx.core.view.ViewTreeObserverOnPreDrawListenerC1064v;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Objects;
import java.util.WeakHashMap;
import kotlin.Pair;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.fragment.app.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1145m extends G0 {
    public final ArrayList c;
    public final H0 d;
    public final H0 e;
    public final z0 f;
    public final Object g;
    public final ArrayList h;
    public final ArrayList i;
    public final C0208f j;
    public final ArrayList k;
    public final ArrayList l;
    public final C0208f m;
    public final C0208f n;
    public final boolean o;
    public final androidx.core.os.b p;
    public Object q;
    public boolean r;

    public C1145m(ArrayList transitionInfos, H0 h0, H0 h02, z0 transitionImpl, Object obj, ArrayList sharedElementFirstOutViews, ArrayList sharedElementLastInViews, C0208f sharedElementNameMapping, ArrayList enteringNames, ArrayList exitingNames, C0208f firstOutViews, C0208f lastInViews, boolean z) {
        Intrinsics.checkNotNullParameter(transitionInfos, "transitionInfos");
        Intrinsics.checkNotNullParameter(transitionImpl, "transitionImpl");
        Intrinsics.checkNotNullParameter(sharedElementFirstOutViews, "sharedElementFirstOutViews");
        Intrinsics.checkNotNullParameter(sharedElementLastInViews, "sharedElementLastInViews");
        Intrinsics.checkNotNullParameter(sharedElementNameMapping, "sharedElementNameMapping");
        Intrinsics.checkNotNullParameter(enteringNames, "enteringNames");
        Intrinsics.checkNotNullParameter(exitingNames, "exitingNames");
        Intrinsics.checkNotNullParameter(firstOutViews, "firstOutViews");
        Intrinsics.checkNotNullParameter(lastInViews, "lastInViews");
        this.c = transitionInfos;
        this.d = h0;
        this.e = h02;
        this.f = transitionImpl;
        this.g = obj;
        this.h = sharedElementFirstOutViews;
        this.i = sharedElementLastInViews;
        this.j = sharedElementNameMapping;
        this.k = enteringNames;
        this.l = exitingNames;
        this.m = firstOutViews;
        this.n = lastInViews;
        this.o = z;
        this.p = new androidx.core.os.b();
    }

    public static void f(View view, ArrayList arrayList) {
        if (!(view instanceof ViewGroup)) {
            if (arrayList.contains(view)) {
                return;
            }
            arrayList.add(view);
            return;
        }
        ViewGroup viewGroup = (ViewGroup) view;
        int i = androidx.core.view.W.a;
        if (viewGroup.isTransitionGroup()) {
            if (arrayList.contains(view)) {
                return;
            }
            arrayList.add(view);
            return;
        }
        int childCount = viewGroup.getChildCount();
        for (int i2 = 0; i2 < childCount; i2++) {
            View child = viewGroup.getChildAt(i2);
            if (child.getVisibility() == 0) {
                Intrinsics.checkNotNullExpressionValue(child, "child");
                f(child, arrayList);
            }
        }
    }

    @Override // androidx.fragment.app.G0
    public final boolean a() {
        Object obj;
        z0 z0Var = this.f;
        if (!z0Var.l()) {
            return false;
        }
        ArrayList arrayList = this.c;
        if (!arrayList.isEmpty()) {
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                C1146n c1146n = (C1146n) it2.next();
                if (Build.VERSION.SDK_INT < 34 || (obj = c1146n.b) == null || !z0Var.m(obj)) {
                    return false;
                }
            }
        }
        Object obj2 = this.g;
        return obj2 == null || z0Var.m(obj2);
    }

    @Override // androidx.fragment.app.G0
    public final void b(ViewGroup container) {
        Intrinsics.checkNotNullParameter(container, "container");
        this.p.a();
    }

    @Override // androidx.fragment.app.G0
    public final void c(ViewGroup container) {
        Object obj;
        Intrinsics.checkNotNullParameter(container, "container");
        boolean zIsLaidOut = container.isLaidOut();
        ArrayList arrayList = this.c;
        if (!zIsLaidOut || this.r) {
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                C1146n c1146n = (C1146n) it2.next();
                H0 h0 = c1146n.a;
                if (AbstractC1136h0.N(2)) {
                    if (this.r) {
                        Objects.toString(h0);
                    } else {
                        container.toString();
                        Objects.toString(h0);
                    }
                }
                c1146n.a.c(this);
            }
            this.r = false;
            return;
        }
        Object obj2 = this.q;
        z0 z0Var = this.f;
        H0 h02 = this.e;
        H0 h03 = this.d;
        if (obj2 != null) {
            z0Var.c(obj2);
            if (AbstractC1136h0.N(2)) {
                Objects.toString(h03);
                Objects.toString(h02);
                return;
            }
            return;
        }
        Pair pairG = g(container, h02, h03);
        ArrayList arrayList2 = (ArrayList) pairG.a;
        ArrayList arrayList3 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            arrayList3.add(((C1146n) it3.next()).a);
        }
        Iterator it4 = arrayList3.iterator();
        while (true) {
            boolean zHasNext = it4.hasNext();
            obj = pairG.b;
            if (!zHasNext) {
                break;
            }
            H0 h04 = (H0) it4.next();
            z0Var.u(h04.c, obj, this.p, new RunnableC1141k(h04, this, 1));
        }
        i(arrayList2, container, new C1143l(this, container, obj));
        if (AbstractC1136h0.N(2)) {
            Objects.toString(h03);
            Objects.toString(h02);
        }
    }

    @Override // androidx.fragment.app.G0
    public final void d(C0030b backEvent, ViewGroup container) {
        Intrinsics.checkNotNullParameter(backEvent, "backEvent");
        Intrinsics.checkNotNullParameter(container, "container");
        Object obj = this.q;
        if (obj != null) {
            this.f.r(obj, backEvent.c);
        }
    }

    @Override // androidx.fragment.app.G0
    public final void e(ViewGroup container) {
        Object obj;
        Intrinsics.checkNotNullParameter(container, "container");
        boolean zIsLaidOut = container.isLaidOut();
        ArrayList arrayList = this.c;
        if (zIsLaidOut) {
            boolean zH = h();
            H0 h0 = this.e;
            H0 h02 = this.d;
            if (zH && (obj = this.g) != null && !a()) {
                Log.i("FragmentManager", "Ignoring shared elements transition " + obj + " between " + h02 + " and " + h0 + " as neither fragment has set a Transition. In order to run a SharedElementTransition, you must also set either an enter or exit transition on a fragment involved in the transaction. The sharedElementTransition will run after the back gesture has been committed.");
            }
            if (a() && h()) {
                kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
                Pair pairG = g(container, h0, h02);
                ArrayList arrayList2 = (ArrayList) pairG.a;
                ArrayList arrayList3 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    arrayList3.add(((C1146n) it2.next()).a);
                }
                Iterator it3 = arrayList3.iterator();
                while (true) {
                    boolean zHasNext = it3.hasNext();
                    Object obj2 = pairG.b;
                    if (!zHasNext) {
                        i(arrayList2, container, new androidx.compose.animation.core.O(this, container, obj2, j, 7));
                        return;
                    }
                    H0 h03 = (H0) it3.next();
                    RunnableC1152u runnableC1152u = new RunnableC1152u(j, 1);
                    Fragment fragment = h03.c;
                    this.f.v(obj2, this.p, runnableC1152u, new RunnableC1141k(h03, this, 0));
                }
            }
        } else {
            Iterator it4 = arrayList.iterator();
            while (it4.hasNext()) {
                H0 h04 = ((C1146n) it4.next()).a;
                if (AbstractC1136h0.N(2)) {
                    container.toString();
                    Objects.toString(h04);
                }
            }
        }
    }

    public final Pair g(ViewGroup viewGroup, H0 h0, H0 h02) {
        ArrayList arrayList;
        ArrayList arrayList2;
        z0 z0Var;
        Object obj;
        Object obj2;
        ArrayList arrayList3;
        ArrayList arrayList4;
        H0 h03 = h0;
        View view = new View(viewGroup.getContext());
        Rect rect = new Rect();
        ArrayList arrayList5 = this.c;
        Iterator it2 = arrayList5.iterator();
        View view2 = null;
        boolean z = false;
        while (true) {
            boolean zHasNext = it2.hasNext();
            arrayList = this.i;
            arrayList2 = this.h;
            z0Var = this.f;
            obj = this.g;
            if (!zHasNext) {
                break;
            }
            if (((C1146n) it2.next()).d == null || h02 == null || h03 == null || this.j.isEmpty() || obj == null) {
                arrayList4 = arrayList5;
            } else {
                C0208f sharedElements = this.m;
                x0 x0Var = s0.a;
                arrayList4 = arrayList5;
                Fragment inFragment = h03.c;
                Intrinsics.checkNotNullParameter(inFragment, "inFragment");
                Fragment outFragment = h02.c;
                Intrinsics.checkNotNullParameter(outFragment, "outFragment");
                Intrinsics.checkNotNullParameter(sharedElements, "sharedElements");
                if (this.o) {
                    outFragment.getEnterTransitionCallback();
                } else {
                    inFragment.getEnterTransitionCallback();
                }
                ViewTreeObserverOnPreDrawListenerC1064v.a(viewGroup, new RunnableC0130g(h03, h02, this, 12));
                arrayList2.addAll(sharedElements.values());
                ArrayList arrayList6 = this.l;
                if (!arrayList6.isEmpty()) {
                    Object obj3 = arrayList6.get(0);
                    Intrinsics.checkNotNullExpressionValue(obj3, "exitingNames[0]");
                    View view3 = (View) sharedElements.get((String) obj3);
                    z0Var.s(view3, obj);
                    view2 = view3;
                }
                C0208f c0208f = this.n;
                arrayList.addAll(c0208f.values());
                ArrayList arrayList7 = this.k;
                if (!arrayList7.isEmpty()) {
                    Object obj4 = arrayList7.get(0);
                    Intrinsics.checkNotNullExpressionValue(obj4, "enteringNames[0]");
                    View view4 = (View) c0208f.get((String) obj4);
                    if (view4 != null) {
                        ViewTreeObserverOnPreDrawListenerC1064v.a(viewGroup, new RunnableC0130g(z0Var, view4, rect, 13));
                        z = true;
                    }
                }
                z0Var.w(obj, view, arrayList2);
                Object obj5 = this.g;
                z0Var.q(obj5, null, null, obj5, arrayList);
            }
            arrayList5 = arrayList4;
        }
        ArrayList arrayList8 = arrayList5;
        ArrayList arrayList9 = arrayList;
        ArrayList arrayList10 = new ArrayList();
        Iterator it3 = arrayList8.iterator();
        Object objO = null;
        Object objO2 = null;
        while (it3.hasNext()) {
            C1146n c1146n = (C1146n) it3.next();
            ArrayList arrayList11 = arrayList9;
            H0 h04 = c1146n.a;
            Iterator it4 = it3;
            Object objH = z0Var.h(c1146n.b);
            if (objH != null) {
                boolean z2 = z;
                ArrayList arrayList12 = new ArrayList();
                ArrayList arrayList13 = arrayList2;
                View view5 = h04.c.mView;
                Object obj6 = obj;
                Intrinsics.checkNotNullExpressionValue(view5, "operation.fragment.mView");
                f(view5, arrayList12);
                if (obj6 != null && (h04 == h02 || h04 == h03)) {
                    if (h04 == h02) {
                        arrayList12.removeAll(CollectionsKt.A0(arrayList13));
                    } else {
                        arrayList12.removeAll(CollectionsKt.A0(arrayList11));
                    }
                }
                if (arrayList12.isEmpty()) {
                    z0Var.a(view, objH);
                    obj2 = objH;
                    arrayList3 = arrayList12;
                } else {
                    z0Var.b(objH, arrayList12);
                    z0Var.q(objH, objH, arrayList12, null, null);
                    obj2 = objH;
                    arrayList3 = arrayList12;
                    if (h04.a == J0.c) {
                        h04.i = false;
                        ArrayList arrayList14 = new ArrayList(arrayList3);
                        Fragment fragment = h04.c;
                        arrayList14.remove(fragment.mView);
                        z0Var.p(obj2, fragment.mView, arrayList14);
                        ViewTreeObserverOnPreDrawListenerC1064v.a(viewGroup, new RunnableC1152u(arrayList3, 2));
                    }
                }
                if (h04.a == J0.b) {
                    arrayList10.addAll(arrayList3);
                    if (z2) {
                        z0Var.t(obj2, rect);
                    }
                    if (AbstractC1136h0.N(2)) {
                        obj2.toString();
                        Iterator it5 = arrayList3.iterator();
                        while (it5.hasNext()) {
                            Object transitioningViews = it5.next();
                            Intrinsics.checkNotNullExpressionValue(transitioningViews, "transitioningViews");
                            Objects.toString((View) transitioningViews);
                        }
                    }
                } else {
                    z0Var.s(view2, obj2);
                    if (AbstractC1136h0.N(2)) {
                        obj2.toString();
                        Iterator it6 = arrayList3.iterator();
                        while (it6.hasNext()) {
                            Object transitioningViews2 = it6.next();
                            Intrinsics.checkNotNullExpressionValue(transitioningViews2, "transitioningViews");
                            Objects.toString((View) transitioningViews2);
                        }
                    }
                }
                if (c1146n.c) {
                    objO = z0Var.o(objO, obj2);
                } else {
                    objO2 = z0Var.o(objO2, obj2);
                }
                h03 = h0;
                arrayList9 = arrayList11;
                it3 = it4;
                z = z2;
                arrayList2 = arrayList13;
                obj = obj6;
            } else {
                h03 = h0;
                arrayList9 = arrayList11;
                it3 = it4;
            }
        }
        Object objN = z0Var.n(objO, objO2, obj);
        if (AbstractC1136h0.N(2)) {
            Objects.toString(objN);
            viewGroup.toString();
        }
        return new Pair(arrayList10, objN);
    }

    public final boolean h() {
        ArrayList arrayList = this.c;
        if (arrayList.isEmpty()) {
            return true;
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            if (!((C1146n) it2.next()).a.c.mTransitioning) {
                return false;
            }
        }
        return true;
    }

    public final void i(ArrayList arrayList, ViewGroup viewGroup, Function0 function0) {
        s0.a(4, arrayList);
        z0 z0Var = this.f;
        ArrayList arrayList2 = new ArrayList();
        ArrayList arrayList3 = this.i;
        int size = arrayList3.size();
        for (int i = 0; i < size; i++) {
            View view = (View) arrayList3.get(i);
            WeakHashMap weakHashMap = androidx.core.view.V.a;
            arrayList2.add(androidx.core.view.L.f(view));
            androidx.core.view.L.n(view, null);
        }
        boolean zN = AbstractC1136h0.N(2);
        ArrayList arrayList4 = this.h;
        if (zN) {
            Iterator it2 = arrayList4.iterator();
            while (it2.hasNext()) {
                Object sharedElementFirstOutViews = it2.next();
                Intrinsics.checkNotNullExpressionValue(sharedElementFirstOutViews, "sharedElementFirstOutViews");
                View view2 = (View) sharedElementFirstOutViews;
                Objects.toString(view2);
                WeakHashMap weakHashMap2 = androidx.core.view.V.a;
                androidx.core.view.L.f(view2);
            }
            Iterator it3 = arrayList3.iterator();
            while (it3.hasNext()) {
                Object sharedElementLastInViews = it3.next();
                Intrinsics.checkNotNullExpressionValue(sharedElementLastInViews, "sharedElementLastInViews");
                View view3 = (View) sharedElementLastInViews;
                Objects.toString(view3);
                WeakHashMap weakHashMap3 = androidx.core.view.V.a;
                androidx.core.view.L.f(view3);
            }
        }
        function0.invoke();
        int size2 = arrayList3.size();
        ArrayList arrayList5 = new ArrayList();
        for (int i2 = 0; i2 < size2; i2++) {
            View view4 = (View) arrayList4.get(i2);
            WeakHashMap weakHashMap4 = androidx.core.view.V.a;
            String strF = androidx.core.view.L.f(view4);
            arrayList5.add(strF);
            if (strF != null) {
                androidx.core.view.L.n(view4, null);
                String str = (String) this.j.get(strF);
                int i3 = 0;
                while (true) {
                    if (i3 >= size2) {
                        break;
                    }
                    if (str.equals(arrayList2.get(i3))) {
                        androidx.core.view.L.n((View) arrayList3.get(i3), strF);
                        break;
                    }
                    i3++;
                }
            }
        }
        ViewTreeObserverOnPreDrawListenerC1064v.a(viewGroup, new y0(size2, arrayList3, arrayList2, arrayList4, arrayList5));
        s0.a(0, arrayList);
        z0Var.x(this.g, arrayList4, arrayList3);
    }
}
