package androidx.fragment.app;

import android.animation.Animator;
import android.animation.AnimatorSet;
import android.os.Bundle;
import android.view.View;
import android.view.animation.Animation;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class J {
    public final Object a;
    public final Cloneable b;

    public J(AbstractC1136h0 fragmentManager) {
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        this.a = fragmentManager;
        this.b = new CopyOnWriteArrayList();
    }

    public void a(Fragment f, boolean z) {
        Intrinsics.checkNotNullParameter(f, "f");
        Fragment fragment = ((AbstractC1136h0) this.a).z;
        if (fragment != null) {
            AbstractC1136h0 parentFragmentManager = fragment.getParentFragmentManager();
            Intrinsics.checkNotNullExpressionValue(parentFragmentManager, "parent.getParentFragmentManager()");
            parentFragmentManager.p.a(f, true);
        }
        Iterator it2 = ((CopyOnWriteArrayList) this.b).iterator();
        while (it2.hasNext()) {
            S s = (S) it2.next();
            if (z) {
                s.getClass();
            }
            AbstractC1124b0 abstractC1124b0 = s.a;
        }
    }

    public void b(Fragment f, boolean z) {
        Intrinsics.checkNotNullParameter(f, "f");
        AbstractC1136h0 abstractC1136h0 = (AbstractC1136h0) this.a;
        I i = abstractC1136h0.x.b;
        Fragment fragment = abstractC1136h0.z;
        if (fragment != null) {
            AbstractC1136h0 parentFragmentManager = fragment.getParentFragmentManager();
            Intrinsics.checkNotNullExpressionValue(parentFragmentManager, "parent.getParentFragmentManager()");
            parentFragmentManager.p.b(f, true);
        }
        Iterator it2 = ((CopyOnWriteArrayList) this.b).iterator();
        while (it2.hasNext()) {
            S s = (S) it2.next();
            if (z) {
                s.getClass();
            }
            AbstractC1124b0 abstractC1124b0 = s.a;
        }
    }

    public void c(Fragment f, boolean z) {
        Intrinsics.checkNotNullParameter(f, "f");
        Fragment fragment = ((AbstractC1136h0) this.a).z;
        if (fragment != null) {
            AbstractC1136h0 parentFragmentManager = fragment.getParentFragmentManager();
            Intrinsics.checkNotNullExpressionValue(parentFragmentManager, "parent.getParentFragmentManager()");
            parentFragmentManager.p.c(f, true);
        }
        Iterator it2 = ((CopyOnWriteArrayList) this.b).iterator();
        while (it2.hasNext()) {
            S s = (S) it2.next();
            if (z) {
                s.getClass();
            }
            AbstractC1124b0 abstractC1124b0 = s.a;
        }
    }

    public void d(Fragment f, boolean z) {
        Intrinsics.checkNotNullParameter(f, "f");
        Fragment fragment = ((AbstractC1136h0) this.a).z;
        if (fragment != null) {
            AbstractC1136h0 parentFragmentManager = fragment.getParentFragmentManager();
            Intrinsics.checkNotNullExpressionValue(parentFragmentManager, "parent.getParentFragmentManager()");
            parentFragmentManager.p.d(f, true);
        }
        Iterator it2 = ((CopyOnWriteArrayList) this.b).iterator();
        while (it2.hasNext()) {
            S s = (S) it2.next();
            if (z) {
                s.getClass();
            }
            AbstractC1124b0 abstractC1124b0 = s.a;
        }
    }

    public void e(Fragment f, boolean z) {
        Intrinsics.checkNotNullParameter(f, "f");
        Fragment fragment = ((AbstractC1136h0) this.a).z;
        if (fragment != null) {
            AbstractC1136h0 parentFragmentManager = fragment.getParentFragmentManager();
            Intrinsics.checkNotNullExpressionValue(parentFragmentManager, "parent.getParentFragmentManager()");
            parentFragmentManager.p.e(f, true);
        }
        Iterator it2 = ((CopyOnWriteArrayList) this.b).iterator();
        while (it2.hasNext()) {
            S s = (S) it2.next();
            if (z) {
                s.getClass();
            }
            AbstractC1124b0 abstractC1124b0 = s.a;
        }
    }

    public void f(Fragment f, boolean z) {
        Intrinsics.checkNotNullParameter(f, "f");
        Fragment fragment = ((AbstractC1136h0) this.a).z;
        if (fragment != null) {
            AbstractC1136h0 parentFragmentManager = fragment.getParentFragmentManager();
            Intrinsics.checkNotNullExpressionValue(parentFragmentManager, "parent.getParentFragmentManager()");
            parentFragmentManager.p.f(f, true);
        }
        Iterator it2 = ((CopyOnWriteArrayList) this.b).iterator();
        while (it2.hasNext()) {
            S s = (S) it2.next();
            if (z) {
                s.getClass();
            }
            s.a.a(f);
        }
    }

    public void g(Fragment f, boolean z) {
        Intrinsics.checkNotNullParameter(f, "f");
        AbstractC1136h0 abstractC1136h0 = (AbstractC1136h0) this.a;
        I i = abstractC1136h0.x.b;
        Fragment fragment = abstractC1136h0.z;
        if (fragment != null) {
            AbstractC1136h0 parentFragmentManager = fragment.getParentFragmentManager();
            Intrinsics.checkNotNullExpressionValue(parentFragmentManager, "parent.getParentFragmentManager()");
            parentFragmentManager.p.g(f, true);
        }
        Iterator it2 = ((CopyOnWriteArrayList) this.b).iterator();
        while (it2.hasNext()) {
            S s = (S) it2.next();
            if (z) {
                s.getClass();
            }
            AbstractC1124b0 abstractC1124b0 = s.a;
        }
    }

    public void h(Fragment f, boolean z) {
        Intrinsics.checkNotNullParameter(f, "f");
        Fragment fragment = ((AbstractC1136h0) this.a).z;
        if (fragment != null) {
            AbstractC1136h0 parentFragmentManager = fragment.getParentFragmentManager();
            Intrinsics.checkNotNullExpressionValue(parentFragmentManager, "parent.getParentFragmentManager()");
            parentFragmentManager.p.h(f, true);
        }
        Iterator it2 = ((CopyOnWriteArrayList) this.b).iterator();
        while (it2.hasNext()) {
            S s = (S) it2.next();
            if (z) {
                s.getClass();
            }
            AbstractC1124b0 abstractC1124b0 = s.a;
        }
    }

    public void i(Fragment f, boolean z) {
        Intrinsics.checkNotNullParameter(f, "f");
        Fragment fragment = ((AbstractC1136h0) this.a).z;
        if (fragment != null) {
            AbstractC1136h0 parentFragmentManager = fragment.getParentFragmentManager();
            Intrinsics.checkNotNullExpressionValue(parentFragmentManager, "parent.getParentFragmentManager()");
            parentFragmentManager.p.i(f, true);
        }
        Iterator it2 = ((CopyOnWriteArrayList) this.b).iterator();
        while (it2.hasNext()) {
            S s = (S) it2.next();
            if (z) {
                s.getClass();
            }
            s.a.b(f);
        }
    }

    public void j(Fragment f, Bundle outState, boolean z) {
        Intrinsics.checkNotNullParameter(f, "f");
        Intrinsics.checkNotNullParameter(outState, "outState");
        Fragment fragment = ((AbstractC1136h0) this.a).z;
        if (fragment != null) {
            AbstractC1136h0 parentFragmentManager = fragment.getParentFragmentManager();
            Intrinsics.checkNotNullExpressionValue(parentFragmentManager, "parent.getParentFragmentManager()");
            parentFragmentManager.p.j(f, outState, true);
        }
        Iterator it2 = ((CopyOnWriteArrayList) this.b).iterator();
        while (it2.hasNext()) {
            S s = (S) it2.next();
            if (z) {
                s.getClass();
            }
            AbstractC1124b0 abstractC1124b0 = s.a;
        }
    }

    public void k(Fragment f, boolean z) {
        Intrinsics.checkNotNullParameter(f, "f");
        Fragment fragment = ((AbstractC1136h0) this.a).z;
        if (fragment != null) {
            AbstractC1136h0 parentFragmentManager = fragment.getParentFragmentManager();
            Intrinsics.checkNotNullExpressionValue(parentFragmentManager, "parent.getParentFragmentManager()");
            parentFragmentManager.p.k(f, true);
        }
        Iterator it2 = ((CopyOnWriteArrayList) this.b).iterator();
        while (it2.hasNext()) {
            S s = (S) it2.next();
            if (z) {
                s.getClass();
            }
            AbstractC1124b0 abstractC1124b0 = s.a;
        }
    }

    public void l(Fragment f, boolean z) {
        Intrinsics.checkNotNullParameter(f, "f");
        Fragment fragment = ((AbstractC1136h0) this.a).z;
        if (fragment != null) {
            AbstractC1136h0 parentFragmentManager = fragment.getParentFragmentManager();
            Intrinsics.checkNotNullExpressionValue(parentFragmentManager, "parent.getParentFragmentManager()");
            parentFragmentManager.p.l(f, true);
        }
        Iterator it2 = ((CopyOnWriteArrayList) this.b).iterator();
        while (it2.hasNext()) {
            S s = (S) it2.next();
            if (z) {
                s.getClass();
            }
            AbstractC1124b0 abstractC1124b0 = s.a;
        }
    }

    public void m(Fragment f, View v, boolean z) {
        Intrinsics.checkNotNullParameter(f, "f");
        Intrinsics.checkNotNullParameter(v, "v");
        Fragment fragment = ((AbstractC1136h0) this.a).z;
        if (fragment != null) {
            AbstractC1136h0 parentFragmentManager = fragment.getParentFragmentManager();
            Intrinsics.checkNotNullExpressionValue(parentFragmentManager, "parent.getParentFragmentManager()");
            parentFragmentManager.p.m(f, v, true);
        }
        Iterator it2 = ((CopyOnWriteArrayList) this.b).iterator();
        while (it2.hasNext()) {
            S s = (S) it2.next();
            if (z) {
                s.getClass();
            }
            AbstractC1124b0 abstractC1124b0 = s.a;
        }
    }

    public void n(Fragment f, boolean z) {
        Intrinsics.checkNotNullParameter(f, "f");
        AbstractC1136h0 abstractC1136h0 = (AbstractC1136h0) this.a;
        Fragment fragment = abstractC1136h0.z;
        if (fragment != null) {
            AbstractC1136h0 parentFragmentManager = fragment.getParentFragmentManager();
            Intrinsics.checkNotNullExpressionValue(parentFragmentManager, "parent.getParentFragmentManager()");
            parentFragmentManager.p.n(f, true);
        }
        Iterator it2 = ((CopyOnWriteArrayList) this.b).iterator();
        while (it2.hasNext()) {
            S s = (S) it2.next();
            if (z) {
                s.getClass();
            }
            s.a.c(abstractC1136h0, f);
        }
    }

    public J(Animation animation) {
        this.a = animation;
        this.b = null;
    }

    public J(Animator animator) {
        this.a = null;
        AnimatorSet animatorSet = new AnimatorSet();
        this.b = animatorSet;
        animatorSet.play(animator);
    }
}
