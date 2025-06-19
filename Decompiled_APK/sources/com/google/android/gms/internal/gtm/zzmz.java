package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import org.json.JSONArray;
import org.json.JSONException;

/* loaded from: classes2.dex */
public final class zzmz extends zzjo {
    private final int zza;
    private final zzhx zzb;

    public zzmz(int i, zzhx zzhxVar) {
        this.zza = i;
        this.zzb = zzhxVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr.length == 1);
        u.b(zzqoVarArr[0] instanceof zzqz);
        try {
            zzjl zzjlVarZza = zzoz.zza(new JSONArray(((zzqz) zzqoVarArr[0]).zzk()).getJSONArray(0));
            zzjlVarZza.zzc(this.zzb);
            return this.zza == 0 ? zzqs.zze : zzjlVarZza.zzd(zzhxVar, new zzqo[0]);
        } catch (JSONException e) {
            zzhi.zzb("Unable to convert Custom Pixie to instruction", e);
            return zzqs.zze;
        }
    }
}
