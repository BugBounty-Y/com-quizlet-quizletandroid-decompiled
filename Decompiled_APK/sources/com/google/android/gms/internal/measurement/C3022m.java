package com.google.android.gms.internal.measurement;

import com.google.android.gms.internal.ads.C1721Kc;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* renamed from: com.google.android.gms.internal.measurement.m, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3022m extends AbstractC2997h {
    public final ArrayList c;
    public final ArrayList d;
    public final C1721Kc e;

    public C3022m(C3022m c3022m) {
        super(c3022m.a);
        ArrayList arrayList = new ArrayList(c3022m.c.size());
        this.c = arrayList;
        arrayList.addAll(c3022m.c);
        ArrayList arrayList2 = new ArrayList(c3022m.d.size());
        this.d = arrayList2;
        arrayList2.addAll(c3022m.d);
        this.e = c3022m.e;
    }

    @Override // com.google.android.gms.internal.measurement.AbstractC2997h
    public final InterfaceC3027n d(C1721Kc c1721Kc, List list) {
        r rVar;
        C1721Kc c1721KcG = this.e.g();
        int i = 0;
        while (true) {
            ArrayList arrayList = this.c;
            int size = arrayList.size();
            rVar = InterfaceC3027n.Q0;
            if (i >= size) {
                break;
            }
            if (i < list.size()) {
                c1721KcG.m((String) arrayList.get(i), ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) list.get(i)));
            } else {
                c1721KcG.m((String) arrayList.get(i), rVar);
            }
            i++;
        }
        Iterator it2 = this.d.iterator();
        while (it2.hasNext()) {
            InterfaceC3027n interfaceC3027n = (InterfaceC3027n) it2.next();
            C3056t c3056t = (C3056t) c1721KcG.c;
            InterfaceC3027n interfaceC3027nA = c3056t.a(c1721KcG, interfaceC3027n);
            if (interfaceC3027nA instanceof C3032o) {
                interfaceC3027nA = c3056t.a(c1721KcG, interfaceC3027n);
            }
            if (interfaceC3027nA instanceof C2987f) {
                return ((C2987f) interfaceC3027nA).a;
            }
        }
        return rVar;
    }

    @Override // com.google.android.gms.internal.measurement.AbstractC2997h, com.google.android.gms.internal.measurement.InterfaceC3027n
    public final InterfaceC3027n j() {
        return new C3022m(this);
    }

    public C3022m(String str, ArrayList arrayList, List list, C1721Kc c1721Kc) {
        super(str);
        this.c = new ArrayList();
        this.e = c1721Kc;
        if (!arrayList.isEmpty()) {
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                this.c.add(((InterfaceC3027n) it2.next()).zzi());
            }
        }
        this.d = new ArrayList(list);
    }
}
