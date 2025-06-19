package com.google.android.gms.internal.ads;

import com.j256.ormlite.stmt.query.SimpleComparison;

/* loaded from: classes2.dex */
public final class Dt implements Bt {
    public static final Is d = new Is(4);
    public final Ft a = new Ft();
    public volatile Bt b;
    public Object c;

    public Dt(Bt bt) {
        this.b = bt;
    }

    public final String toString() {
        Object objB = this.b;
        if (objB == d) {
            objB = android.support.v4.media.session.a.B("<supplier that returned ", String.valueOf(this.c), SimpleComparison.GREATER_THAN_OPERATION);
        }
        return android.support.v4.media.session.a.B("Suppliers.memoize(", String.valueOf(objB), ")");
    }

    @Override // com.google.android.gms.internal.ads.Bt
    public final Object zza() {
        Bt bt = this.b;
        Is is = d;
        if (bt != is) {
            synchronized (this.a) {
                try {
                    if (this.b != is) {
                        Object objZza = this.b.zza();
                        this.c = objZza;
                        this.b = is;
                        return objZza;
                    }
                } finally {
                }
            }
        }
        return this.c;
    }
}
