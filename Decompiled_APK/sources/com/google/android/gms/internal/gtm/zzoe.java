package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
public final class zzoe extends zzjo {
    private static final zzqq zza = new zzqq(Double.valueOf(0.0d));
    private static final zzqq zzb = new zzqq(Double.valueOf(2.147483647E9d));

    private static final boolean zzb(zzqo zzqoVar) {
        return (zzqoVar instanceof zzqq) && !Double.isNaN(((zzqq) zzqoVar).zzi().doubleValue());
    }

    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        int length = zzqoVarArr.length;
        zzqo zzqoVar = length > 0 ? zzqoVarArr[0] : zza;
        zzqo zzqoVar2 = length > 1 ? zzqoVarArr[1] : zzb;
        double dDoubleValue = 0.0d;
        double dDoubleValue2 = 2.147483647E9d;
        if (zzb(zzqoVar) && zzb(zzqoVar2) && zzjn.zzf(zzqoVar, zzqoVar2)) {
            dDoubleValue = ((zzqq) zzqoVar).zzi().doubleValue();
            dDoubleValue2 = ((zzqq) zzqoVar2).zzi().doubleValue();
        }
        return new zzqq(Double.valueOf(Math.round(((dDoubleValue2 - dDoubleValue) * Math.random()) + dDoubleValue)));
    }
}
