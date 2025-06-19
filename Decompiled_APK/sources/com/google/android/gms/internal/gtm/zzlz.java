package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzlz extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) throws NumberFormatException {
        u.b(zzqoVarArr.length == 2);
        double dZzb = zzjn.zzb(zzqoVarArr[0]);
        double dZzb2 = zzjn.zzb(zzqoVarArr[1]);
        return (Double.isNaN(dZzb) || Double.isNaN(dZzb2)) ? new zzqq(Double.valueOf(Double.NaN)) : (Double.isInfinite(dZzb) || dZzb2 == 0.0d) ? new zzqq(Double.valueOf(Double.NaN)) : (Double.isInfinite(dZzb) || !Double.isInfinite(dZzb2)) ? (dZzb != 0.0d || dZzb2 == 0.0d || Double.isInfinite(dZzb2)) ? new zzqq(Double.valueOf(dZzb % dZzb2)) : new zzqq(Double.valueOf(dZzb)) : new zzqq(Double.valueOf(dZzb));
    }
}
