package com.google.android.gms.internal.gtm;

import com.amazon.device.ads.DTBMetricsConfiguration;
import com.google.android.gms.common.internal.u;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzot extends zzjo {
    private static final zztp zza = zztp.zzj("GET", "HEAD", "POST", "PUT");
    private final zzgw zzb;

    public zzot(zzgw zzgwVar) {
        this.zzb = zzgwVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr.length == 1);
        u.b(zzqoVarArr[0] instanceof zzqw);
        zzqo zzqoVarZzb = zzqoVarArr[0].zzb(DTBMetricsConfiguration.APSMETRICS_URL);
        u.b(zzqoVarZzb instanceof zzqz);
        String strZzk = ((zzqz) zzqoVarZzb).zzk();
        zzqo zzqoVarZzb2 = zzqoVarArr[0].zzb("method");
        zzqs zzqsVar = zzqs.zze;
        if (zzqoVarZzb2 == zzqsVar) {
            zzqoVarZzb2 = new zzqz("GET");
        }
        u.b(zzqoVarZzb2 instanceof zzqz);
        String strZzk2 = ((zzqz) zzqoVarZzb2).zzk();
        u.b(zza.contains(strZzk2));
        zzqo zzqoVarZzb3 = zzqoVarArr[0].zzb("uniqueId");
        u.b(zzqoVarZzb3 == zzqsVar || zzqoVarZzb3 == zzqs.zzd || (zzqoVarZzb3 instanceof zzqz));
        String strZzk3 = (zzqoVarZzb3 == zzqsVar || zzqoVarZzb3 == zzqs.zzd) ? null : ((zzqz) zzqoVarZzb3).zzk();
        zzqo zzqoVarZzb4 = zzqoVarArr[0].zzb("headers");
        u.b(zzqoVarZzb4 == zzqsVar || (zzqoVarZzb4 instanceof zzqw));
        HashMap map = new HashMap();
        if (zzqoVarZzb4 == zzqsVar) {
            map = null;
        } else {
            for (Map.Entry entry : ((zzqw) zzqoVarZzb4).zzi().entrySet()) {
                String str = (String) entry.getKey();
                zzqo zzqoVar = (zzqo) entry.getValue();
                if (zzqoVar instanceof zzqz) {
                    map.put(str, ((zzqz) zzqoVar).zzk());
                } else {
                    zzhi.zze("Ignore the non-string value of header key " + str + ".");
                }
            }
        }
        zzqo zzqoVarZzb5 = zzqoVarArr[0].zzb("body");
        zzqs zzqsVar2 = zzqs.zze;
        u.b(zzqoVarZzb5 == zzqsVar2 || (zzqoVarZzb5 instanceof zzqz));
        String strZzk4 = zzqoVarZzb5 != zzqsVar2 ? ((zzqz) zzqoVarZzb5).zzk() : null;
        if ((strZzk2.equals("GET") || strZzk2.equals("HEAD")) && strZzk4 != null) {
            zzhi.zze("Body of " + strZzk2 + " hit will be ignored: " + strZzk4 + ".");
        }
        HashMap map2 = map;
        this.zzb.zzb(strZzk, strZzk2, strZzk3, map2, strZzk4);
        zzhi.zzd(String.format("QueueRequest:\n  url = %s,\n  method = %s,\n  uniqueId = %s,\n  headers = %s,\n  body = %s", strZzk, strZzk2, strZzk3, map2, strZzk4));
        return zzqsVar2;
    }
}
