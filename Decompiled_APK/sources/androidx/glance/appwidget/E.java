package androidx.glance.appwidget;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3332e;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.collections.CollectionsKt;

/* loaded from: classes.dex */
public final class E extends androidx.glance.m {
    public long d;
    public J0 e;

    public E() {
        super(0, 3);
        this.d = 9205357640488583168L;
        this.e = I0.a;
    }

    @Override // androidx.glance.k
    public final androidx.glance.p a() {
        androidx.glance.p pVarA;
        androidx.glance.k kVar = (androidx.glance.k) CollectionsKt.k0(this.c);
        return (kVar == null || (pVarA = kVar.a()) == null) ? AbstractC3332e.d(androidx.glance.n.a) : pVarA;
    }

    @Override // androidx.glance.k
    public final void b(androidx.glance.p pVar) {
        throw new IllegalAccessError("You cannot set the modifier of an EmittableSizeBox");
    }

    @Override // androidx.glance.k
    public final androidx.glance.k copy() {
        E e = new E();
        e.d = this.d;
        e.e = this.e;
        ArrayList arrayList = e.c;
        ArrayList arrayList2 = this.c;
        ArrayList arrayList3 = new ArrayList(kotlin.collections.C.q(arrayList2, 10));
        Iterator it2 = arrayList2.iterator();
        while (it2.hasNext()) {
            arrayList3.add(((androidx.glance.k) it2.next()).copy());
        }
        arrayList.addAll(arrayList3);
        return e;
    }

    public final String toString() {
        return "EmittableSizeBox(size=" + ((Object) androidx.compose.ui.unit.g.c(this.d)) + ", sizeMode=" + this.e + ", children=[\n" + c() + "\n])";
    }
}
