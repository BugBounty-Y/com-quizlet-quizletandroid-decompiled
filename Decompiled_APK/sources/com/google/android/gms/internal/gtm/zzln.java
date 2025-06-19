package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzln extends zzjo {
    public static final zzln zza = new zzln();

    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) throws NumberFormatException {
        u.b(zzqoVarArr.length == 2);
        zzqo zzqoVar = zzqoVarArr[0];
        zzqo zzqoVar2 = zzqoVarArr[1];
        u.b(!zzra.zzi(zzqoVar));
        u.b(!zzra.zzi(zzqoVar2));
        String strZzd = zzjn.zzd(zzqoVar2);
        if (zzqoVar instanceof zzqv) {
            if ("length".equals(strZzd)) {
                return new zzqp(Boolean.TRUE);
            }
            double dZzb = zzjn.zzb(zzqoVar2);
            if (dZzb == Math.floor(dZzb)) {
                int i = (int) dZzb;
                if (strZzd.equals(Integer.toString(i)) && i >= 0 && i < ((zzqv) zzqoVar).zzk().size()) {
                    return new zzqp(Boolean.TRUE);
                }
            }
        } else if (zzqoVar instanceof zzqz) {
            if ("length".equals(strZzd)) {
                return new zzqp(Boolean.TRUE);
            }
            double dZzb2 = zzjn.zzb(zzqoVar2);
            if (dZzb2 == Math.floor(dZzb2)) {
                int i2 = (int) dZzb2;
                if (strZzd.equals(Integer.toString(i2)) && i2 >= 0 && i2 < ((zzqz) zzqoVar).zzk().length()) {
                    return new zzqp(Boolean.TRUE);
                }
            }
            return new zzqp(Boolean.FALSE);
        }
        return new zzqp(Boolean.valueOf(zzqoVar.zzh(strZzd)));
    }
}
