package com.iab.omid.library.amazon.internal;

import com.google.android.gms.internal.ads.Sr;
import com.iab.omid.library.amazon.adsession.k;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class a implements d {
    public static final a f;
    public com.google.mlkit.common.internal.model.a a;
    public Date b;
    public boolean c;
    public Sr d;
    public boolean e;

    static {
        Sr sr = new Sr(1);
        a aVar = new a();
        aVar.a = new com.google.mlkit.common.internal.model.a(21);
        aVar.d = sr;
        f = aVar;
    }

    @Override // com.iab.omid.library.amazon.internal.d
    public final void a(boolean z) {
        if (!this.e && z) {
            this.a.getClass();
            Date date = new Date();
            Date date2 = this.b;
            if (date2 == null || date.after(date2)) {
                this.b = date;
                if (this.c) {
                    Iterator it2 = Collections.unmodifiableCollection(c.c.b).iterator();
                    while (it2.hasNext()) {
                        com.iab.omid.library.amazon.publisher.a aVar = ((k) it2.next()).e;
                        Date date3 = this.b;
                        aVar.c(date3 != null ? (Date) date3.clone() : null);
                    }
                }
            }
        }
        this.e = z;
    }
}
