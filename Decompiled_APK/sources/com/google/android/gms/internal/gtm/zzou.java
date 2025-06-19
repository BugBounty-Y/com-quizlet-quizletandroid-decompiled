package com.google.android.gms.internal.gtm;

import android.os.RemoteException;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzou extends zzjo {
    private final com.google.android.gms.tagmanager.zzck zza;
    private final zzht zzb;

    public zzou(com.google.android.gms.tagmanager.zzck zzckVar, zzht zzhtVar) {
        this.zza = zzckVar;
        this.zzb = zzhtVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        boolean z;
        int length = zzqoVarArr.length;
        boolean z2 = true;
        if (length == 1) {
            z = true;
        } else if (length == 2) {
            length = 2;
            z = true;
        } else {
            z = false;
        }
        u.b(z);
        u.b(zzqoVarArr[0] instanceof zzqz);
        zzqo zzqoVar = length > 1 ? zzqoVarArr[1] : zzqs.zze;
        zzqs zzqsVar = zzqs.zze;
        if (zzqoVar != zzqsVar && !(zzqoVar instanceof zzqw)) {
            z2 = false;
        }
        u.b(z2);
        zzgt zzgtVarZza = this.zzb.zza();
        try {
            this.zza.zzc(zzgtVarZza.zzc(), ((zzqz) zzqoVarArr[0]).zzk(), zzqoVar != zzqsVar ? zzra.zza(((zzqw) zzqoVar).zzi()) : null, zzgtVarZza.currentTimeMillis());
        } catch (RemoteException e) {
            zzhi.zza("Error calling measurement proxy:".concat(String.valueOf(e.getMessage())));
        }
        return zzqs.zze;
    }
}
