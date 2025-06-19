package androidx.camera.core;

import androidx.camera.core.impl.InterfaceC0183w;
import androidx.camera.core.impl.InterfaceC0185y;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;

/* renamed from: androidx.camera.core.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0192o {
    public static final C0192o b;
    public static final C0192o c;
    public final LinkedHashSet a;

    static {
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        linkedHashSet.add(new androidx.camera.core.impl.T(0));
        b = new C0192o(linkedHashSet);
        LinkedHashSet linkedHashSet2 = new LinkedHashSet();
        linkedHashSet2.add(new androidx.camera.core.impl.T(1));
        c = new C0192o(linkedHashSet2);
    }

    public C0192o(LinkedHashSet linkedHashSet) {
        this.a = linkedHashSet;
    }

    public final ArrayList a(ArrayList arrayList) {
        ArrayList arrayList2 = new ArrayList(arrayList);
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            InterfaceC0191n interfaceC0191n = (InterfaceC0191n) it2.next();
            List<InterfaceC0183w> listUnmodifiableList = Collections.unmodifiableList(arrayList2);
            androidx.camera.core.impl.T t = (androidx.camera.core.impl.T) interfaceC0191n;
            t.getClass();
            ArrayList arrayList3 = new ArrayList();
            for (InterfaceC0183w interfaceC0183w : listUnmodifiableList) {
                AbstractC3242q6.c("The camera info doesn't contain internal implementation.", interfaceC0183w instanceof InterfaceC0183w);
                if (interfaceC0183w.e() == t.b) {
                    arrayList3.add(interfaceC0183w);
                }
            }
            arrayList2 = arrayList3;
        }
        arrayList2.retainAll(arrayList);
        return arrayList2;
    }

    public final Integer b() {
        Iterator it2 = this.a.iterator();
        Integer num = null;
        while (it2.hasNext()) {
            InterfaceC0191n interfaceC0191n = (InterfaceC0191n) it2.next();
            if (interfaceC0191n instanceof androidx.camera.core.impl.T) {
                Integer numValueOf = Integer.valueOf(((androidx.camera.core.impl.T) interfaceC0191n).b);
                if (num == null) {
                    num = numValueOf;
                } else if (!num.equals(numValueOf)) {
                    throw new IllegalStateException("Multiple conflicting lens facing requirements exist.");
                }
            }
        }
        return num;
    }

    public final InterfaceC0185y c(LinkedHashSet linkedHashSet) {
        ArrayList arrayList = new ArrayList();
        Iterator it2 = linkedHashSet.iterator();
        while (it2.hasNext()) {
            arrayList.add(((InterfaceC0185y) it2.next()).n());
        }
        ArrayList arrayListA = a(arrayList);
        LinkedHashSet linkedHashSet2 = new LinkedHashSet();
        Iterator it3 = linkedHashSet.iterator();
        while (it3.hasNext()) {
            InterfaceC0185y interfaceC0185y = (InterfaceC0185y) it3.next();
            if (arrayListA.contains(interfaceC0185y.n())) {
                linkedHashSet2.add(interfaceC0185y);
            }
        }
        Iterator it4 = linkedHashSet2.iterator();
        if (it4.hasNext()) {
            return (InterfaceC0185y) it4.next();
        }
        throw new IllegalArgumentException("No available camera can be found");
    }
}
