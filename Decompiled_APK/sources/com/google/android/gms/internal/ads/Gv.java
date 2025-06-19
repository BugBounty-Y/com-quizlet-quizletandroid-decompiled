package com.google.android.gms.internal.ads;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* loaded from: classes2.dex */
public final class Gv extends Av {
    public List p;

    public Gv(AbstractC2330lu abstractC2330lu, boolean z) {
        List arrayList;
        super(abstractC2330lu, z, true);
        if (abstractC2330lu.isEmpty()) {
            arrayList = Collections.EMPTY_LIST;
        } else {
            int size = abstractC2330lu.size();
            AbstractC2543qs.g(size, "initialArraySize");
            arrayList = new ArrayList(size);
        }
        for (int i = 0; i < abstractC2330lu.size(); i++) {
            arrayList.add(null);
        }
        this.p = arrayList;
        z();
    }

    @Override // com.google.android.gms.internal.ads.Av
    public final void t(int i) {
        this.l = null;
        this.p = null;
    }

    @Override // com.google.android.gms.internal.ads.Av
    public final void x(int i, Object obj) {
        List list = this.p;
        if (list != null) {
            list.set(i, new Hv(obj));
        }
    }

    @Override // com.google.android.gms.internal.ads.Av
    public final void y() {
        List<Hv> list = this.p;
        if (list != null) {
            int size = list.size();
            AbstractC2543qs.g(size, "initialArraySize");
            ArrayList arrayList = new ArrayList(size);
            for (Hv hv : list) {
                arrayList.add(hv != null ? hv.a : null);
            }
            g(Collections.unmodifiableList(arrayList));
        }
    }
}
