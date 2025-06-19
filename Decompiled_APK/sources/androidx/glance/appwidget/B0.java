package androidx.glance.appwidget;

import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class B0 extends androidx.glance.m {
    public final int d;
    public androidx.glance.p e;

    public B0(int i) {
        super(i, 2);
        this.d = i;
        this.e = androidx.glance.n.a;
    }

    @Override // androidx.glance.k
    public final androidx.glance.p a() {
        return this.e;
    }

    @Override // androidx.glance.k
    public final void b(androidx.glance.p pVar) {
        this.e = pVar;
    }

    @Override // androidx.glance.k
    public final androidx.glance.k copy() {
        B0 b0 = new B0(this.d);
        b0.e = this.e;
        ArrayList arrayList = b0.c;
        ArrayList arrayList2 = this.c;
        ArrayList arrayList3 = new ArrayList(kotlin.collections.C.q(arrayList2, 10));
        Iterator it2 = arrayList2.iterator();
        while (it2.hasNext()) {
            arrayList3.add(((androidx.glance.k) it2.next()).copy());
        }
        arrayList.addAll(arrayList3);
        return b0;
    }

    public final String toString() {
        return "RemoteViewsRoot(modifier=" + this.e + ", children=[\n" + c() + "\n])";
    }
}
