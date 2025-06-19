package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzlm extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) throws NumberFormatException {
        zzqo zzqoVarZzi;
        u.b(zzqoVarArr.length == 2);
        zzqo zzqoVar = zzqoVarArr[0];
        boolean z = zzqoVar instanceof zzqz;
        zzqo zzqoVar2 = zzqoVarArr[1];
        u.b(z || !zzra.zzj(zzqoVar));
        u.b(!zzra.zzi(zzqoVar));
        u.b(!zzra.zzi(zzqoVar2));
        String strZzd = zzjn.zzd(zzqoVar2);
        if (zzqoVar instanceof zzqv) {
            zzqv zzqvVar = (zzqv) zzqoVar;
            if ("length".equals(strZzd)) {
                return new zzqq(Double.valueOf(zzqvVar.zzk().size()));
            }
            double dZzb = zzjn.zzb(zzqoVar2);
            if (dZzb == Math.floor(dZzb)) {
                int i = (int) dZzb;
                if (strZzd.equals(Integer.toString(i)) && (zzqoVarZzi = zzqvVar.zzi(i)) != zzqs.zze) {
                    return zzqoVarZzi;
                }
            }
        } else if (z) {
            zzqz zzqzVar = (zzqz) zzqoVar;
            if ("length".equals(strZzd)) {
                return new zzqq(Double.valueOf(zzqzVar.zzk().length()));
            }
            double dZzb2 = zzjn.zzb(zzqoVar2);
            if (dZzb2 == Math.floor(dZzb2)) {
                int i2 = (int) dZzb2;
                if (strZzd.equals(Integer.toString(i2))) {
                    return zzqzVar.zzi(i2);
                }
            }
            return zzqs.zze;
        }
        return zzqoVar.zzb(strZzd);
    }
}
