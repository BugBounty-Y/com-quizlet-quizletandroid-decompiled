package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public abstract class zzoq extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr.length == 2);
        try {
            double dZzb = zzjn.zzb(zzqoVarArr[0]);
            double dZzb2 = zzjn.zzb(zzqoVarArr[1]);
            return (Double.isNaN(dZzb) || Double.isNaN(dZzb2)) ? new zzqp(Boolean.FALSE) : new zzqp(Boolean.valueOf(zzb(dZzb, dZzb2)));
        } catch (IllegalArgumentException unused) {
            return new zzqp(Boolean.FALSE);
        }
    }

    public abstract boolean zzb(double d, double d2);
}
