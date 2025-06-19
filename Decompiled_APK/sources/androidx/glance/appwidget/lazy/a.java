package androidx.glance.appwidget.lazy;

import androidx.glance.k;
import androidx.glance.m;
import androidx.glance.n;
import androidx.glance.p;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.collections.C;

/* loaded from: classes.dex */
public final class a extends m {
    public p d;
    public int e;

    public a() {
        super(0, 1);
        this.d = n.a;
        this.e = 0;
    }

    @Override // androidx.glance.k
    public final p a() {
        return this.d;
    }

    @Override // androidx.glance.k
    public final void b(p pVar) {
        this.d = pVar;
    }

    @Override // androidx.glance.k
    public final k copy() {
        a aVar = new a();
        aVar.d = this.d;
        aVar.e = this.e;
        ArrayList arrayList = aVar.c;
        ArrayList arrayList2 = this.c;
        ArrayList arrayList3 = new ArrayList(C.q(arrayList2, 10));
        Iterator it2 = arrayList2.iterator();
        while (it2.hasNext()) {
            arrayList3.add(((k) it2.next()).copy());
        }
        arrayList.addAll(arrayList3);
        return aVar;
    }

    public final String toString() {
        return "EmittableLazyList(modifier=" + this.d + ", horizontalAlignment=" + ((Object) androidx.glance.layout.a.b(this.e)) + ", activityOptions=null, children=[\n" + c() + "\n])";
    }
}
