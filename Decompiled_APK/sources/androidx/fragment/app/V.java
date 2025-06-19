package androidx.fragment.app;

import androidx.activity.C0030b;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class V extends androidx.activity.D {
    public final /* synthetic */ AbstractC1136h0 d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public V(AbstractC1136h0 abstractC1136h0) {
        super(false);
        this.d = abstractC1136h0;
    }

    @Override // androidx.activity.D
    public final void a() {
        boolean zN = AbstractC1136h0.N(3);
        AbstractC1136h0 abstractC1136h0 = this.d;
        if (zN) {
            Objects.toString(abstractC1136h0);
        }
        abstractC1136h0.getClass();
        if (AbstractC1136h0.N(3)) {
            Objects.toString(abstractC1136h0.h);
        }
        C1121a c1121a = abstractC1136h0.h;
        if (c1121a != null) {
            c1121a.s = false;
            c1121a.f();
            C1121a c1121a2 = abstractC1136h0.h;
            RunnableC1152u runnableC1152u = new RunnableC1152u(abstractC1136h0, 4);
            if (c1121a2.q == null) {
                c1121a2.q = new ArrayList();
            }
            c1121a2.q.add(runnableC1152u);
            abstractC1136h0.h.g();
            abstractC1136h0.i = true;
            abstractC1136h0.A(true);
            abstractC1136h0.H();
            abstractC1136h0.i = false;
            abstractC1136h0.h = null;
        }
    }

    @Override // androidx.activity.D
    public final void b() {
        boolean zN = AbstractC1136h0.N(3);
        AbstractC1136h0 abstractC1136h0 = this.d;
        if (zN) {
            Objects.toString(abstractC1136h0);
        }
        abstractC1136h0.i = true;
        abstractC1136h0.A(true);
        abstractC1136h0.i = false;
        C1121a c1121a = abstractC1136h0.h;
        V v = abstractC1136h0.j;
        if (c1121a == null) {
            if (v.a) {
                AbstractC1136h0.N(3);
                abstractC1136h0.W();
                return;
            } else {
                AbstractC1136h0.N(3);
                abstractC1136h0.g.c();
                return;
            }
        }
        ArrayList arrayList = abstractC1136h0.o;
        if (!arrayList.isEmpty()) {
            LinkedHashSet<Fragment> linkedHashSet = new LinkedHashSet(AbstractC1136h0.I(abstractC1136h0.h));
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                InterfaceC1128d0 interfaceC1128d0 = (InterfaceC1128d0) it2.next();
                for (Fragment fragment : linkedHashSet) {
                    interfaceC1128d0.getClass();
                }
            }
        }
        Iterator it3 = abstractC1136h0.h.a.iterator();
        while (it3.hasNext()) {
            Fragment fragment2 = ((r0) it3.next()).b;
            if (fragment2 != null) {
                fragment2.mTransitioning = false;
            }
        }
        Iterator it4 = abstractC1136h0.g(new ArrayList(Collections.singletonList(abstractC1136h0.h)), 0, 1).iterator();
        while (it4.hasNext()) {
            C1147o c1147o = (C1147o) it4.next();
            c1147o.getClass();
            AbstractC1136h0.N(3);
            ArrayList arrayList2 = c1147o.c;
            c1147o.l(arrayList2);
            c1147o.c(arrayList2);
        }
        Iterator it5 = abstractC1136h0.h.a.iterator();
        while (it5.hasNext()) {
            Fragment fragment3 = ((r0) it5.next()).b;
            if (fragment3 != null && fragment3.mContainer == null) {
                abstractC1136h0.h(fragment3).i();
            }
        }
        abstractC1136h0.h = null;
        abstractC1136h0.m0();
        if (AbstractC1136h0.N(3)) {
            boolean z = v.a;
            abstractC1136h0.toString();
        }
    }

    @Override // androidx.activity.D
    public final void c(C0030b backEvent) {
        boolean zN = AbstractC1136h0.N(2);
        AbstractC1136h0 abstractC1136h0 = this.d;
        if (zN) {
            Objects.toString(abstractC1136h0);
        }
        if (abstractC1136h0.h != null) {
            Iterator it2 = abstractC1136h0.g(new ArrayList(Collections.singletonList(abstractC1136h0.h)), 0, 1).iterator();
            while (it2.hasNext()) {
                C1147o c1147o = (C1147o) it2.next();
                c1147o.getClass();
                Intrinsics.checkNotNullParameter(backEvent, "backEvent");
                if (AbstractC1136h0.N(2)) {
                    float f = backEvent.c;
                }
                ArrayList arrayList = c1147o.c;
                ArrayList arrayList2 = new ArrayList();
                Iterator it3 = arrayList.iterator();
                while (it3.hasNext()) {
                    kotlin.collections.G.u(arrayList2, ((H0) it3.next()).k);
                }
                List listW0 = CollectionsKt.w0(CollectionsKt.A0(arrayList2));
                int size = listW0.size();
                for (int i = 0; i < size; i++) {
                    ((G0) listW0.get(i)).d(backEvent, c1147o.a);
                }
            }
            Iterator it4 = abstractC1136h0.o.iterator();
            while (it4.hasNext()) {
                ((InterfaceC1128d0) it4.next()).getClass();
            }
        }
    }

    @Override // androidx.activity.D
    public final void d(C0030b c0030b) {
        boolean zN = AbstractC1136h0.N(3);
        AbstractC1136h0 abstractC1136h0 = this.d;
        if (zN) {
            Objects.toString(abstractC1136h0);
        }
        abstractC1136h0.x();
        abstractC1136h0.y(new C1134g0(abstractC1136h0), false);
    }
}
