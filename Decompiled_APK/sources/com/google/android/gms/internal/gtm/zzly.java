package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzly extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) throws NumberFormatException {
        u.b(zzqoVarArr.length == 2);
        double dZzb = zzjn.zzb(zzqoVarArr[0]);
        double dZzb2 = zzjn.zzb(zzqoVarArr[1]);
        if (Double.isNaN(dZzb) || Double.isNaN(dZzb2)) {
            return new zzqq(Double.valueOf(Double.NaN));
        }
        if (Double.isInfinite(dZzb) && Double.isInfinite(dZzb2)) {
            return new zzqq(Double.valueOf(Double.NaN));
        }
        boolean z = (((double) Double.compare(dZzb, 0.0d)) < 0.0d) ^ (((double) Double.compare(dZzb2, 0.0d)) < 0.0d);
        if (Double.isInfinite(dZzb) && !Double.isInfinite(dZzb2)) {
            return new zzqq(Double.valueOf(true != z ? Double.POSITIVE_INFINITY : Double.NEGATIVE_INFINITY));
        }
        if (!Double.isInfinite(dZzb) && Double.isInfinite(dZzb2)) {
            return new zzqq(Double.valueOf(0.0d));
        }
        if (dZzb == 0.0d) {
            return dZzb2 == 0.0d ? new zzqq(Double.valueOf(Double.NaN)) : new zzqq(Double.valueOf(0.0d));
        }
        if (Double.isInfinite(dZzb) || dZzb == 0.0d || dZzb2 != 0.0d) {
            return new zzqq(Double.valueOf(dZzb / dZzb2));
        }
        return new zzqq(Double.valueOf(true != z ? Double.POSITIVE_INFINITY : Double.NEGATIVE_INFINITY));
    }
}
