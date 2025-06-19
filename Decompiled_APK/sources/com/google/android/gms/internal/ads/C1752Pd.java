package com.google.android.gms.internal.ads;

import java.util.ArrayList;
import java.util.Iterator;

/* renamed from: com.google.android.gms.internal.ads.Pd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1752Pd implements Iterable {
    public final ArrayList a = new ArrayList();

    public final boolean a(InterfaceC2529qe interfaceC2529qe) {
        ArrayList arrayList = new ArrayList();
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            C1746Od c1746Od = (C1746Od) it2.next();
            if (c1746Od.c == interfaceC2529qe) {
                arrayList.add(c1746Od);
            }
        }
        if (arrayList.isEmpty()) {
            return false;
        }
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            ((C1746Od) it3.next()).d.l();
        }
        return true;
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        return this.a.iterator();
    }
}
