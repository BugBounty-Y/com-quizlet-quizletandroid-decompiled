package com.google.android.gms.internal.gtm;

import android.net.Uri;
import com.google.android.gms.common.internal.u;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzov extends zzjo {
    private final zzgw zza;

    public zzov(zzgw zzgwVar) {
        this.zza = zzgwVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        int length = zzqoVarArr.length;
        u.b(length > 0);
        zzqo zzqoVar = zzqoVarArr[0];
        u.b(!(zzqoVar instanceof zzqs));
        zzqo zzqoVar2 = length > 1 ? zzqoVarArr[1] : zzqs.zze;
        zzqs zzqsVar = zzqs.zze;
        u.b(zzqoVar2 == zzqsVar || (zzqoVar2 instanceof zzqv));
        zzqo zzqoVar3 = length > 2 ? zzqoVarArr[2] : zzqsVar;
        u.b(zzqoVar3 == zzqsVar || !(zzqoVar3 instanceof zzqs));
        Uri.Builder builderBuildUpon = Uri.parse(zzjn.zzd(zzqoVar)).buildUpon();
        if (zzqoVar2 != zzqsVar) {
            for (zzqo zzqoVar4 : ((zzqv) zzqoVar2).zzk()) {
                u.b(zzqoVar4 instanceof zzqw);
                for (Map.Entry entry : ((zzqw) zzqoVar4).zzi().entrySet()) {
                    builderBuildUpon.appendQueryParameter(((String) entry.getKey()).toString(), zzjn.zzd(zzra.zzc(zzhxVar, (zzqo) entry.getValue())));
                }
            }
        }
        String string = builderBuildUpon.build().toString();
        zzqs zzqsVar2 = zzqs.zze;
        if (zzqoVar3 == zzqsVar2) {
            ((zzgr) this.zza).zzb(string, null, null, null, null);
            zzhi.zzd("SendPixel: url = ".concat(String.valueOf(string)));
            return zzqsVar2;
        }
        String strZzd = zzjn.zzd(zzqoVar3);
        ((zzgr) this.zza).zzb(string, null, strZzd, null, null);
        zzhi.zzd("SendPixel: url = " + string + ", uniqueId = " + strZzd);
        return zzqsVar2;
    }
}
