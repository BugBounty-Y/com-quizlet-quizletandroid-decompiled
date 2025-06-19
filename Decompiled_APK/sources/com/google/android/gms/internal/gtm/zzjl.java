package com.google.android.gms.internal.gtm;

import androidx.compose.ui.node.B;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzjl extends zzjo {
    private zzhx zza = null;
    private final String zzb;
    private final List zzc;
    private final List zzd;

    public zzjl(zzhx zzhxVar, String str, List list, List list2) {
        this.zzb = str;
        this.zzc = list;
        this.zzd = list2;
    }

    public final String toString() {
        List list = this.zzd;
        String string = this.zzc.toString();
        String string2 = list.toString();
        StringBuilder sb = new StringBuilder();
        B.u(sb, this.zzb, "\n\tparams: ", string, "\n\t: statements: ");
        sb.append(string2);
        return sb.toString();
    }

    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        try {
            zzhx zzhxVarZza = this.zza.zza();
            for (int i = 0; i < this.zzc.size(); i++) {
                if (zzqoVarArr.length > i) {
                    zzhxVarZza.zzc((String) this.zzc.get(i), zzqoVarArr[i]);
                } else {
                    zzhxVarZza.zzc((String) this.zzc.get(i), zzqs.zze);
                }
            }
            zzhxVarZza.zzc("arguments", new zzqv(Arrays.asList(zzqoVarArr)));
            Iterator it2 = this.zzd.iterator();
            while (it2.hasNext()) {
                zzqo zzqoVarZzd = zzra.zzd(zzhxVarZza, (zzqx) it2.next());
                if (zzqoVarZzd instanceof zzqs) {
                    zzqs zzqsVar = (zzqs) zzqoVarZzd;
                    if (zzqsVar.zzj()) {
                        return zzqsVar.zzi();
                    }
                }
            }
        } catch (RuntimeException e) {
            zzhi.zza("Internal error - Function call: " + this.zzb + "\n" + e.getMessage());
        }
        return zzqs.zze;
    }

    public final String zzb() {
        return this.zzb;
    }

    public final void zzc(zzhx zzhxVar) {
        this.zza = zzhxVar;
    }
}
