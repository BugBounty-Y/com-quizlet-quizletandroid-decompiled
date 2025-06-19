package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzma extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) throws NumberFormatException {
        u.b(zzqoVarArr.length == 2);
        double dZzb = zzjn.zzb(zzqoVarArr[0]);
        double dZzb2 = zzjn.zzb(zzqoVarArr[1]);
        if (Double.isNaN(dZzb) || Double.isNaN(dZzb2)) {
            return new zzqq(Double.valueOf(Double.NaN));
        }
        if ((Double.isInfinite(dZzb) && dZzb2 == 0.0d) || (dZzb == 0.0d && Double.isInfinite(dZzb2))) {
            return new zzqq(Double.valueOf(Double.NaN));
        }
        if (Double.isInfinite(dZzb) || Double.isInfinite(dZzb2)) {
            return new zzqq(Double.valueOf(true != (((((double) Double.compare(dZzb, 0.0d)) > 0.0d ? 1 : (((double) Double.compare(dZzb, 0.0d)) == 0.0d ? 0 : -1)) < 0) ^ (((double) Double.compare(dZzb2, 0.0d)) < 0.0d)) ? Double.POSITIVE_INFINITY : Double.NEGATIVE_INFINITY));
        }
        return new zzqq(Double.valueOf(dZzb * dZzb2));
    }
}
