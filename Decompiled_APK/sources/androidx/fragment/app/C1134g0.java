package androidx.fragment.app;

import android.util.Log;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Objects;

/* renamed from: androidx.fragment.app.g0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1134g0 implements InterfaceC1130e0 {
    public final /* synthetic */ AbstractC1136h0 a;

    public C1134g0(AbstractC1136h0 abstractC1136h0) {
        this.a = abstractC1136h0;
    }

    @Override // androidx.fragment.app.InterfaceC1130e0
    public final boolean a(ArrayList arrayList, ArrayList arrayList2) {
        ArrayList arrayList3;
        ArrayList arrayList4;
        boolean zY;
        AbstractC1136h0 abstractC1136h0 = this.a;
        abstractC1136h0.getClass();
        if (AbstractC1136h0.N(2)) {
            Objects.toString(abstractC1136h0.a);
        }
        if (abstractC1136h0.d.isEmpty()) {
            Log.i("FragmentManager", "Ignoring call to start back stack pop because the back stack is empty.");
            arrayList3 = arrayList;
            zY = false;
            arrayList4 = arrayList2;
        } else {
            C1121a c1121a = (C1121a) android.support.v4.media.session.a.e(1, abstractC1136h0.d);
            abstractC1136h0.h = c1121a;
            Iterator it2 = c1121a.a.iterator();
            while (it2.hasNext()) {
                Fragment fragment = ((r0) it2.next()).b;
                if (fragment != null) {
                    fragment.mTransitioning = true;
                }
            }
            arrayList3 = arrayList;
            arrayList4 = arrayList2;
            zY = abstractC1136h0.Y(arrayList3, arrayList4, null, -1, 0);
        }
        if (!abstractC1136h0.o.isEmpty() && arrayList3.size() > 0) {
            ((Boolean) arrayList4.get(arrayList3.size() - 1)).getClass();
            LinkedHashSet<Fragment> linkedHashSet = new LinkedHashSet();
            Iterator it3 = arrayList3.iterator();
            while (it3.hasNext()) {
                linkedHashSet.addAll(AbstractC1136h0.I((C1121a) it3.next()));
            }
            Iterator it4 = abstractC1136h0.o.iterator();
            while (it4.hasNext()) {
                InterfaceC1128d0 interfaceC1128d0 = (InterfaceC1128d0) it4.next();
                for (Fragment fragment2 : linkedHashSet) {
                    interfaceC1128d0.getClass();
                }
            }
        }
        return zY;
    }
}
