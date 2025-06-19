package androidx.fragment.app;

import android.view.View;
import android.view.ViewGroup;
import androidx.collection.C0208f;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.fragment.app.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1147o {
    public final ViewGroup a;
    public final ArrayList b;
    public final ArrayList c;
    public boolean d;
    public boolean e;
    public boolean f;

    public C1147o(ViewGroup container) {
        Intrinsics.checkNotNullParameter(container, "container");
        this.a = container;
        this.b = new ArrayList();
        this.c = new ArrayList();
    }

    public static void f(C0208f c0208f, View view) {
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        String strF = androidx.core.view.L.f(view);
        if (strF != null) {
            c0208f.put(strF, view);
        }
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            int childCount = viewGroup.getChildCount();
            for (int i = 0; i < childCount; i++) {
                View child = viewGroup.getChildAt(i);
                if (child.getVisibility() == 0) {
                    Intrinsics.checkNotNullExpressionValue(child, "child");
                    f(c0208f, child);
                }
            }
        }
    }

    public static final C1147o j(ViewGroup container, AbstractC1136h0 fragmentManager) {
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        Y factory = fragmentManager.M();
        Intrinsics.checkNotNullExpressionValue(factory, "fragmentManager.specialEffectsControllerFactory");
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter(factory, "factory");
        Object tag = container.getTag(R.id.special_effects_controller_view_tag);
        if (tag instanceof C1147o) {
            return (C1147o) tag;
        }
        factory.getClass();
        Intrinsics.checkNotNullParameter(container, "container");
        C1147o c1147o = new C1147o(container);
        Intrinsics.checkNotNullExpressionValue(c1147o, "factory.createController(container)");
        container.setTag(R.id.special_effects_controller_view_tag, c1147o);
        return c1147o;
    }

    public static boolean k(ArrayList arrayList) {
        boolean z;
        Iterator it2 = arrayList.iterator();
        loop0: while (true) {
            z = true;
            while (it2.hasNext()) {
                H0 h0 = (H0) it2.next();
                if (!h0.k.isEmpty()) {
                    ArrayList arrayList2 = h0.k;
                    if (arrayList2 == null || !arrayList2.isEmpty()) {
                        Iterator it3 = arrayList2.iterator();
                        while (it3.hasNext()) {
                            if (!((G0) it3.next()).a()) {
                                break;
                            }
                        }
                    }
                }
                z = false;
            }
            break loop0;
        }
        if (z) {
            ArrayList arrayList3 = new ArrayList();
            Iterator it4 = arrayList.iterator();
            while (it4.hasNext()) {
                kotlin.collections.G.u(arrayList3, ((H0) it4.next()).k);
            }
            if (!arrayList3.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    public final void a(H0 operation) {
        Intrinsics.checkNotNullParameter(operation, "operation");
        if (operation.i) {
            J0 j0 = operation.a;
            View viewRequireView = operation.c.requireView();
            Intrinsics.checkNotNullExpressionValue(viewRequireView, "operation.fragment.requireView()");
            j0.a(viewRequireView, this.a);
            operation.i = false;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:151:0x0441 A[LOOP:18: B:149:0x043b->B:151:0x0441, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x009b  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0122  */
    /* JADX WARN: Removed duplicated region for block: B:9:0x004a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(java.util.ArrayList r29, boolean r30) throws android.content.res.Resources.NotFoundException {
        /*
            Method dump skipped, instructions count: 1302
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.fragment.app.C1147o.b(java.util.ArrayList, boolean):void");
    }

    public final void c(ArrayList operations) {
        Intrinsics.checkNotNullParameter(operations, "operations");
        ArrayList arrayList = new ArrayList();
        Iterator it2 = operations.iterator();
        while (it2.hasNext()) {
            kotlin.collections.G.u(arrayList, ((H0) it2.next()).k);
        }
        List listW0 = CollectionsKt.w0(CollectionsKt.A0(arrayList));
        int size = listW0.size();
        for (int i = 0; i < size; i++) {
            ((G0) listW0.get(i)).c(this.a);
        }
        int size2 = operations.size();
        for (int i2 = 0; i2 < size2; i2++) {
            a((H0) operations.get(i2));
        }
        List listW02 = CollectionsKt.w0(operations);
        int size3 = listW02.size();
        for (int i3 = 0; i3 < size3; i3++) {
            H0 h0 = (H0) listW02.get(i3);
            if (h0.k.isEmpty()) {
                h0.b();
            }
        }
    }

    public final void d(J0 j0, I0 i0, o0 o0Var) {
        synchronized (this.b) {
            try {
                Fragment fragment = o0Var.c;
                Intrinsics.checkNotNullExpressionValue(fragment, "fragmentStateManager.fragment");
                H0 h0G = g(fragment);
                if (h0G == null) {
                    Fragment fragment2 = o0Var.c;
                    if (fragment2.mTransitioning || fragment2.mRemoving) {
                        Intrinsics.checkNotNullExpressionValue(fragment2, "fragmentStateManager.fragment");
                        h0G = h(fragment2);
                    } else {
                        h0G = null;
                    }
                }
                if (h0G != null) {
                    h0G.d(j0, i0);
                    return;
                }
                H0 h0 = new H0(j0, i0, o0Var);
                this.b.add(h0);
                F0 listener = new F0(this, h0, 0);
                Intrinsics.checkNotNullParameter(listener, "listener");
                h0.d.add(listener);
                F0 listener2 = new F0(this, h0, 2);
                Intrinsics.checkNotNullParameter(listener2, "listener");
                h0.d.add(listener2);
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void e() {
        if (this.f) {
            return;
        }
        if (!this.a.isAttachedToWindow()) {
            i();
            this.e = false;
            return;
        }
        synchronized (this.b) {
            try {
                ArrayList arrayListY0 = CollectionsKt.y0(this.c);
                this.c.clear();
                Iterator it2 = arrayListY0.iterator();
                while (it2.hasNext()) {
                    H0 h0 = (H0) it2.next();
                    h0.g = !this.b.isEmpty() && h0.c.mTransitioning;
                }
                Iterator it3 = arrayListY0.iterator();
                while (it3.hasNext()) {
                    H0 h02 = (H0) it3.next();
                    if (this.d) {
                        if (AbstractC1136h0.N(2)) {
                            Objects.toString(h02);
                        }
                        h02.b();
                    } else {
                        if (AbstractC1136h0.N(2)) {
                            Objects.toString(h02);
                        }
                        h02.a(this.a);
                    }
                    this.d = false;
                    if (!h02.f) {
                        this.c.add(h02);
                    }
                }
                if (!this.b.isEmpty()) {
                    m();
                    ArrayList arrayListY02 = CollectionsKt.y0(this.b);
                    if (arrayListY02.isEmpty()) {
                        return;
                    }
                    this.b.clear();
                    this.c.addAll(arrayListY02);
                    AbstractC1136h0.N(2);
                    b(arrayListY02, this.e);
                    boolean zK = k(arrayListY02);
                    Iterator it4 = arrayListY02.iterator();
                    boolean z = true;
                    while (it4.hasNext()) {
                        if (!((H0) it4.next()).c.mTransitioning) {
                            z = false;
                        }
                    }
                    this.d = z && !zK;
                    AbstractC1136h0.N(2);
                    if (!z) {
                        l(arrayListY02);
                        c(arrayListY02);
                    } else if (zK) {
                        l(arrayListY02);
                        int size = arrayListY02.size();
                        for (int i = 0; i < size; i++) {
                            a((H0) arrayListY02.get(i));
                        }
                    }
                    this.e = false;
                    AbstractC1136h0.N(2);
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final H0 g(Fragment fragment) {
        Object next;
        Iterator it2 = this.b.iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            H0 h0 = (H0) next;
            if (Intrinsics.b(h0.c, fragment) && !h0.e) {
                break;
            }
        }
        return (H0) next;
    }

    public final H0 h(Fragment fragment) {
        Object next;
        Iterator it2 = this.c.iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            H0 h0 = (H0) next;
            if (Intrinsics.b(h0.c, fragment) && !h0.e) {
                break;
            }
        }
        return (H0) next;
    }

    public final void i() {
        AbstractC1136h0.N(2);
        boolean zIsAttachedToWindow = this.a.isAttachedToWindow();
        synchronized (this.b) {
            try {
                m();
                l(this.b);
                ArrayList arrayListY0 = CollectionsKt.y0(this.c);
                Iterator it2 = arrayListY0.iterator();
                while (it2.hasNext()) {
                    ((H0) it2.next()).g = false;
                }
                Iterator it3 = arrayListY0.iterator();
                while (it3.hasNext()) {
                    H0 h0 = (H0) it3.next();
                    if (AbstractC1136h0.N(2)) {
                        if (!zIsAttachedToWindow) {
                            Objects.toString(this.a);
                        }
                        Objects.toString(h0);
                    }
                    h0.a(this.a);
                }
                ArrayList arrayListY02 = CollectionsKt.y0(this.b);
                Iterator it4 = arrayListY02.iterator();
                while (it4.hasNext()) {
                    ((H0) it4.next()).g = false;
                }
                Iterator it5 = arrayListY02.iterator();
                while (it5.hasNext()) {
                    H0 h02 = (H0) it5.next();
                    if (AbstractC1136h0.N(2)) {
                        if (!zIsAttachedToWindow) {
                            Objects.toString(this.a);
                        }
                        Objects.toString(h02);
                    }
                    h02.a(this.a);
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void l(ArrayList arrayList) {
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            H0 h0 = (H0) arrayList.get(i);
            if (!h0.h) {
                h0.h = true;
                I0 i0 = h0.b;
                I0 i02 = I0.b;
                o0 o0Var = h0.l;
                if (i0 == i02) {
                    Fragment fragment = o0Var.c;
                    Intrinsics.checkNotNullExpressionValue(fragment, "fragmentStateManager.fragment");
                    View viewFindFocus = fragment.mView.findFocus();
                    if (viewFindFocus != null) {
                        fragment.setFocusedView(viewFindFocus);
                        if (AbstractC1136h0.N(2)) {
                            viewFindFocus.toString();
                            fragment.toString();
                        }
                    }
                    View viewRequireView = h0.c.requireView();
                    Intrinsics.checkNotNullExpressionValue(viewRequireView, "this.fragment.requireView()");
                    if (viewRequireView.getParent() == null) {
                        if (AbstractC1136h0.N(2)) {
                            fragment.toString();
                            viewRequireView.toString();
                        }
                        o0Var.a();
                        viewRequireView.setAlpha(DefinitionKt.NO_Float_VALUE);
                    }
                    if (viewRequireView.getAlpha() == DefinitionKt.NO_Float_VALUE && viewRequireView.getVisibility() == 0) {
                        if (AbstractC1136h0.N(2)) {
                            viewRequireView.toString();
                        }
                        viewRequireView.setVisibility(4);
                    }
                    viewRequireView.setAlpha(fragment.getPostOnViewCreatedAlpha());
                    if (AbstractC1136h0.N(2)) {
                        fragment.getPostOnViewCreatedAlpha();
                    }
                } else if (i0 == I0.c) {
                    Fragment fragment2 = o0Var.c;
                    Intrinsics.checkNotNullExpressionValue(fragment2, "fragmentStateManager.fragment");
                    View viewRequireView2 = fragment2.requireView();
                    Intrinsics.checkNotNullExpressionValue(viewRequireView2, "fragment.requireView()");
                    if (AbstractC1136h0.N(2)) {
                        Objects.toString(viewRequireView2.findFocus());
                        viewRequireView2.toString();
                        fragment2.toString();
                    }
                    viewRequireView2.clearFocus();
                }
            }
        }
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            kotlin.collections.G.u(arrayList2, ((H0) it2.next()).k);
        }
        List listW0 = CollectionsKt.w0(CollectionsKt.A0(arrayList2));
        int size2 = listW0.size();
        for (int i2 = 0; i2 < size2; i2++) {
            G0 g0 = (G0) listW0.get(i2);
            g0.getClass();
            ViewGroup container = this.a;
            Intrinsics.checkNotNullParameter(container, "container");
            if (!g0.a) {
                g0.e(container);
            }
            g0.a = true;
        }
    }

    public final void m() {
        J0 j0;
        Iterator it2 = this.b.iterator();
        while (it2.hasNext()) {
            H0 h0 = (H0) it2.next();
            if (h0.b == I0.b) {
                View viewRequireView = h0.c.requireView();
                Intrinsics.checkNotNullExpressionValue(viewRequireView, "fragment.requireView()");
                int visibility = viewRequireView.getVisibility();
                if (visibility == 0) {
                    j0 = J0.b;
                } else if (visibility == 4) {
                    j0 = J0.d;
                } else {
                    if (visibility != 8) {
                        throw new IllegalArgumentException(android.support.v4.media.session.a.f(visibility, "Unknown visibility "));
                    }
                    j0 = J0.c;
                }
                h0.d(j0, I0.a);
            }
        }
    }
}
