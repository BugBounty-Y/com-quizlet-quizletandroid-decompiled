package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzls extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) throws NumberFormatException {
        boolean z = false;
        u.b(zzqoVarArr.length == 3);
        zzqo zzqoVar = zzqoVarArr[0];
        zzqo zzqoVar2 = zzqoVarArr[1];
        zzqo zzqoVar3 = zzqoVarArr[2];
        u.b(zzqoVar != zzqs.zzd);
        u.b(zzqoVar != zzqs.zze);
        u.b(!zzra.zzi(zzqoVar));
        u.b(!zzra.zzi(zzqoVar2));
        u.b(!zzra.zzi(zzqoVar3));
        if (!zzra.zzj(zzqoVar)) {
            String strZzd = zzjn.zzd(zzqoVar2);
            if (!(zzqoVar instanceof zzqw)) {
                if (zzqoVar instanceof zzqv) {
                    zzqv zzqvVar = (zzqv) zzqoVar;
                    if ("length".equals(strZzd)) {
                        double dZzb = zzjn.zzb(zzqoVar3);
                        if (!Double.isInfinite(dZzb) && dZzb == Math.floor(dZzb)) {
                            z = true;
                        }
                        u.b(z);
                        zzqvVar.zzm((int) dZzb);
                        return zzqoVar3;
                    }
                    double dZzb2 = zzjn.zzb(zzqoVar2);
                    if (!Double.isInfinite(dZzb2) && dZzb2 >= 0.0d) {
                        int i = (int) dZzb2;
                        if (strZzd.equals(Integer.toString(i))) {
                            zzqvVar.zzl(i, zzqoVar3);
                            return zzqoVar3;
                        }
                    }
                }
                zzqoVar.zzf(strZzd, zzqoVar3);
                return zzqoVar3;
            }
            zzqw zzqwVar = (zzqw) zzqoVar;
            if (!zzqwVar.zzk()) {
                zzqwVar.zzf(strZzd, zzqoVar3);
            }
        }
        return zzqoVar3;
    }
}
