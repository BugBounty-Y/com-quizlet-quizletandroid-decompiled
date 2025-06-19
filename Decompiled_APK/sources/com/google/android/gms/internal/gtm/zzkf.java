package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.Comparator;

/* loaded from: classes2.dex */
final class zzkf implements Comparator {
    final /* synthetic */ zzqr zza;
    final /* synthetic */ zzhx zzb;

    public zzkf(zzki zzkiVar, zzqr zzqrVar, zzhx zzhxVar) {
        this.zza = zzqrVar;
        this.zzb = zzhxVar;
    }

    @Override // java.util.Comparator
    public final /* bridge */ /* synthetic */ int compare(Object obj, Object obj2) {
        zzqo zzqoVar = (zzqo) obj;
        zzqo zzqoVar2 = (zzqo) obj2;
        if (zzqoVar == null) {
            return zzqoVar2 != null ? 1 : 0;
        }
        if (zzqoVar2 == null) {
            return -1;
        }
        zzqo zzqoVarZzd = this.zza.zzi().zzd(this.zzb, zzqoVar, zzqoVar2);
        u.k(zzqoVarZzd instanceof zzqq);
        return (int) ((zzqq) zzqoVarZzd).zzi().doubleValue();
    }
}
