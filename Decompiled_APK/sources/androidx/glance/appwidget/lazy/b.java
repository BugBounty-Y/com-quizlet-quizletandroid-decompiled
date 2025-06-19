package androidx.glance.appwidget.lazy;

import androidx.glance.k;
import androidx.glance.m;
import androidx.glance.p;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3332e;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.collections.C;

/* loaded from: classes.dex */
public final class b extends m {
    public androidx.glance.layout.c d;
    public p e;
    public long f;

    public b() {
        super(0, 3);
        this.d = androidx.glance.layout.c.e;
        this.e = AbstractC3332e.e(new androidx.glance.layout.m(androidx.glance.unit.f.a));
    }

    @Override // androidx.glance.k
    public final p a() {
        return this.e;
    }

    @Override // androidx.glance.k
    public final void b(p pVar) {
        this.e = pVar;
    }

    @Override // androidx.glance.k
    public final k copy() {
        b bVar = new b();
        bVar.f = this.f;
        bVar.d = this.d;
        ArrayList arrayList = bVar.c;
        ArrayList arrayList2 = this.c;
        ArrayList arrayList3 = new ArrayList(C.q(arrayList2, 10));
        Iterator it2 = arrayList2.iterator();
        while (it2.hasNext()) {
            arrayList3.add(((k) it2.next()).copy());
        }
        arrayList.addAll(arrayList3);
        return bVar;
    }

    public final String toString() {
        return "EmittableLazyListItem(modifier=" + this.e + ", alignment=" + this.d + ", children=[\n" + c() + "\n])";
    }
}
