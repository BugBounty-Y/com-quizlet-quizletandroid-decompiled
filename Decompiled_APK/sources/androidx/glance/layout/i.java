package androidx.glance.layout;

import java.util.ArrayList;
import java.util.Iterator;
import kotlin.collections.C;

/* loaded from: classes.dex */
public final class i extends androidx.glance.m {
    public androidx.glance.p d;
    public c e;

    public i() {
        super(0, 3);
        this.d = androidx.glance.n.a;
        this.e = c.c;
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
        i iVar = new i();
        iVar.d = this.d;
        iVar.e = this.e;
        ArrayList arrayList = iVar.c;
        ArrayList arrayList2 = this.c;
        ArrayList arrayList3 = new ArrayList(C.q(arrayList2, 10));
        Iterator it2 = arrayList2.iterator();
        while (it2.hasNext()) {
            arrayList3.add(((androidx.glance.k) it2.next()).copy());
        }
        arrayList.addAll(arrayList3);
        return iVar;
    }

    public final String toString() {
        return "EmittableBox(modifier=" + this.d + ", contentAlignment=" + this.e + "children=[\n" + c() + "\n])";
    }
}
