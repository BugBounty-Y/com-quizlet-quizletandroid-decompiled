package androidx.glance.layout;

import java.util.ArrayList;
import java.util.Iterator;
import kotlin.collections.C;

/* loaded from: classes.dex */
public final class k extends androidx.glance.m {
    public androidx.glance.p d;
    public int e;
    public int f;

    public k() {
        super(0, 3);
        this.d = androidx.glance.n.a;
        this.e = 0;
        this.f = 0;
    }

    @Override // androidx.glance.k
    public final androidx.glance.p a() {
        return this.d;
    }

    @Override // androidx.glance.k
    public final void b(androidx.glance.p pVar) {
        this.d = pVar;
    }

    @Override // androidx.glance.k
    public final androidx.glance.k copy() {
        k kVar = new k();
        kVar.d = this.d;
        kVar.e = this.e;
        kVar.f = this.f;
        ArrayList arrayList = kVar.c;
        ArrayList arrayList2 = this.c;
        ArrayList arrayList3 = new ArrayList(C.q(arrayList2, 10));
        Iterator it2 = arrayList2.iterator();
        while (it2.hasNext()) {
            arrayList3.add(((androidx.glance.k) it2.next()).copy());
        }
        arrayList.addAll(arrayList3);
        return kVar;
    }

    public final String toString() {
        return "EmittableRow(modifier=" + this.d + ", horizontalAlignment=" + ((Object) a.b(this.e)) + ", verticalAlignment=" + ((Object) b.b(this.f)) + ", children=[\n" + c() + "\n])";
    }
}
