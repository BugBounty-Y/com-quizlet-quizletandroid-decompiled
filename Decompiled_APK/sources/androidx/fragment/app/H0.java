package androidx.fragment.app;

import android.view.ViewGroup;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Objects;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class H0 {
    public J0 a;
    public I0 b;
    public final Fragment c;
    public final ArrayList d;
    public boolean e;
    public boolean f;
    public boolean g;
    public boolean h;
    public boolean i;
    public final ArrayList j;
    public final ArrayList k;
    public final o0 l;

    public H0(J0 finalState, I0 lifecycleImpact, o0 fragmentStateManager) {
        Intrinsics.checkNotNullParameter(finalState, "finalState");
        Intrinsics.checkNotNullParameter(lifecycleImpact, "lifecycleImpact");
        Intrinsics.checkNotNullParameter(fragmentStateManager, "fragmentStateManager");
        Fragment fragment = fragmentStateManager.c;
        Intrinsics.checkNotNullExpressionValue(fragment, "fragmentStateManager.fragment");
        Intrinsics.checkNotNullParameter(finalState, "finalState");
        Intrinsics.checkNotNullParameter(lifecycleImpact, "lifecycleImpact");
        Intrinsics.checkNotNullParameter(fragment, "fragment");
        this.a = finalState;
        this.b = lifecycleImpact;
        this.c = fragment;
        this.d = new ArrayList();
        this.i = true;
        ArrayList arrayList = new ArrayList();
        this.j = arrayList;
        this.k = arrayList;
        this.l = fragmentStateManager;
    }

    public final void a(ViewGroup container) {
        Intrinsics.checkNotNullParameter(container, "container");
        this.h = false;
        if (this.e) {
            return;
        }
        this.e = true;
        if (this.j.isEmpty()) {
            b();
            return;
        }
        for (G0 g0 : CollectionsKt.w0(this.k)) {
            g0.getClass();
            Intrinsics.checkNotNullParameter(container, "container");
            if (!g0.b) {
                g0.b(container);
            }
            g0.b = true;
        }
    }

    public final void b() {
        this.h = false;
        if (!this.f) {
            if (AbstractC1136h0.N(2)) {
                toString();
            }
            this.f = true;
            Iterator it2 = this.d.iterator();
            while (it2.hasNext()) {
                ((Runnable) it2.next()).run();
            }
        }
        this.c.mTransitioning = false;
        this.l.i();
    }

    public final void c(G0 effect) {
        Intrinsics.checkNotNullParameter(effect, "effect");
        ArrayList arrayList = this.j;
        if (arrayList.remove(effect) && arrayList.isEmpty()) {
            b();
        }
    }

    public final void d(J0 finalState, I0 lifecycleImpact) {
        Intrinsics.checkNotNullParameter(finalState, "finalState");
        Intrinsics.checkNotNullParameter(lifecycleImpact, "lifecycleImpact");
        int iOrdinal = lifecycleImpact.ordinal();
        J0 j0 = J0.a;
        Fragment fragment = this.c;
        if (iOrdinal == 0) {
            if (this.a != j0) {
                if (AbstractC1136h0.N(2)) {
                    Objects.toString(fragment);
                    Objects.toString(this.a);
                    Objects.toString(finalState);
                }
                this.a = finalState;
                return;
            }
            return;
        }
        if (iOrdinal == 1) {
            if (this.a == j0) {
                if (AbstractC1136h0.N(2)) {
                    Objects.toString(fragment);
                    Objects.toString(this.b);
                }
                this.a = J0.b;
                this.b = I0.b;
                this.i = true;
                return;
            }
            return;
        }
        if (iOrdinal != 2) {
            return;
        }
        if (AbstractC1136h0.N(2)) {
            Objects.toString(fragment);
            Objects.toString(this.a);
            Objects.toString(this.b);
        }
        this.a = j0;
        this.b = I0.c;
        this.i = true;
    }

    public final String toString() {
        StringBuilder sbY = android.support.v4.media.session.a.y("Operation {", Integer.toHexString(System.identityHashCode(this)), "} {finalState = ");
        sbY.append(this.a);
        sbY.append(" lifecycleImpact = ");
        sbY.append(this.b);
        sbY.append(" fragment = ");
        sbY.append(this.c);
        sbY.append('}');
        return sbY.toString();
    }
}
