package androidx.glance.layout;

import java.util.ArrayList;
import java.util.Iterator;
import kotlin.collections.C;

/* loaded from: classes.dex */
public final class j extends androidx.glance.m {
    public androidx.glance.p d;
    public int e;
    public int f;

    public j() {
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
        j jVar = new j();
        jVar.d = this.d;
        jVar.e = this.e;
        jVar.f = this.f;
        ArrayList arrayList = jVar.c;
        ArrayList arrayList2 = this.c;
        ArrayList arrayList3 = new ArrayList(C.q(arrayList2, 10));
        Iterator it2 = arrayList2.iterator();
        while (it2.hasNext()) {
            arrayList3.add(((androidx.glance.k) it2.next()).copy());
        }
        arrayList.addAll(arrayList3);
        return jVar;
    }

    public final String toString() {
        return "EmittableColumn(modifier=" + this.d + ", verticalAlignment=" + ((Object) b.b(this.e)) + ", horizontalAlignment=" + ((Object) a.b(this.f)) + ", children=[\n" + c() + "\n])";
    }
}
