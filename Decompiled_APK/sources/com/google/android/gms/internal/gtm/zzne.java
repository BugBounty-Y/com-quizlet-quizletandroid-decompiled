package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
public final class zzne extends zzjo {
    private final zzht zza;

    public zzne(zzht zzhtVar) {
        this.zza = zzhtVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        zzqo zzqoVar;
        int length = zzqoVarArr.length;
        if (length != 0) {
            zzqo zzqoVar2 = zzqoVarArr[0];
            zzqs zzqsVar = zzqs.zze;
            if (zzqoVar2 != zzqsVar) {
                Object obj = this.zza.zza().zzd().get("_ldl");
                if (obj == null) {
                    return new zzqz("");
                }
                zzqo zzqoVarZzb = zzra.zzb(obj);
                if (!(zzqoVarZzb instanceof zzqz)) {
                    return new zzqz("");
                }
                String strZzk = ((zzqz) zzqoVarZzb).zzk();
                if (!zzhh.zza(strZzk, "conv").equals(zzjn.zzd(zzqoVarArr[0]))) {
                    return new zzqz("");
                }
                String strZzd = null;
                if (length > 1 && (zzqoVar = zzqoVarArr[1]) != zzqsVar) {
                    strZzd = zzjn.zzd(zzqoVar);
                }
                String strZza = zzhh.zza(strZzk, strZzd);
                return strZza != null ? new zzqz(strZza) : new zzqz("");
            }
        }
        return new zzqz("");
    }
}
