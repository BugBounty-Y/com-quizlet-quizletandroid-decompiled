package com.google.android.gms.internal.ads;

import java.util.Collections;
import java.util.Date;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class Or implements Rr {
    public static final Or e = new Or(new Sr(0));
    public boolean a;
    public boolean b;
    public Object c;
    public final Object d;

    public Or(Sr sr) {
        this.d = sr;
    }

    @Override // com.google.android.gms.internal.ads.Rr
    public void a(boolean z) {
        if (!this.b && z) {
            Date date = new Date();
            Date date2 = (Date) this.c;
            if (date2 == null || date.after(date2)) {
                this.c = date;
                if (this.a) {
                    Iterator it2 = Collections.unmodifiableCollection(Qr.c.b).iterator();
                    while (it2.hasNext()) {
                        Zr zr = ((Hr) it2.next()).d;
                        Date date3 = (Date) this.c;
                        zr.c(date3 != null ? (Date) date3.clone() : null);
                    }
                }
            }
        }
        this.b = z;
    }

    public Or(C2326lq c2326lq, Os os, C2711up c2711up) {
        this.a = false;
        this.b = false;
        this.c = c2711up;
        com.google.common.util.concurrent.e eVarI = ((C2881yn) os.b).I(c2711up.b, c2711up.a, null);
        com.google.android.gms.ads.internal.c cVar = new com.google.android.gms.ads.internal.c(this, os, c2326lq, c2711up, 6);
        Xv xv = c2711up.e;
        this.d = AbstractC2025es.A(AbstractC2025es.N(eVarI, cVar, xv), Exception.class, new D9(this, os), xv);
    }
}
