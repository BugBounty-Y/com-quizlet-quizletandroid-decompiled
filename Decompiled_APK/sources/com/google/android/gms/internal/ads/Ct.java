package com.google.android.gms.internal.ads;

import com.j256.ormlite.stmt.query.SimpleComparison;
import java.io.Serializable;

/* loaded from: classes2.dex */
public final class Ct implements Serializable, Bt {
    public final transient Ft a = new Ft();
    public final Bt b;
    public volatile transient boolean c;
    public transient Object d;

    public Ct(Bt bt) {
        this.b = bt;
    }

    public final String toString() {
        return android.support.v4.media.session.a.B("Suppliers.memoize(", (this.c ? android.support.v4.media.session.a.B("<supplier that returned ", String.valueOf(this.d), SimpleComparison.GREATER_THAN_OPERATION) : this.b).toString(), ")");
    }

    @Override // com.google.android.gms.internal.ads.Bt
    public final Object zza() {
        if (!this.c) {
            synchronized (this.a) {
                try {
                    if (!this.c) {
                        Object objZza = this.b.zza();
                        this.d = objZza;
                        this.c = true;
                        return objZza;
                    }
                } finally {
                }
            }
        }
        return this.d;
    }
}
