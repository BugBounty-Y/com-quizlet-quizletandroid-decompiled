package com.google.android.gms.internal.gtm;

import android.content.Context;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.common.util.a;
import com.google.android.gms.common.util.b;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzpe {
    final Map zza;
    private final Context zzb;
    private final zzpq zzc;
    private final a zzd;
    private final Map zze;

    public zzpe(Context context) {
        HashMap map = new HashMap();
        zzpq zzpqVar = new zzpq(context);
        b bVar = b.a;
        this.zza = new HashMap();
        this.zzb = context.getApplicationContext();
        this.zzd = bVar;
        this.zzc = zzpqVar;
        this.zze = map;
    }

    public final void zzb(zzpj zzpjVar, List list, int i, zzpb zzpbVar, zzgo zzgoVar) {
        if (i == 0) {
            zzhi.zzd("Starting to fetch a new resource");
            i = 0;
        }
        int i2 = i;
        if (i2 >= list.size()) {
            String strConcat = "There is no valid resource for the container: ".concat(String.valueOf(zzpjVar.zza().zzb()));
            zzhi.zzd(strConcat);
            zzpbVar.zza(new zzpl(new Status(16, strConcat, null, null), ((Integer) list.get(i2 - 1)).intValue(), null, null));
            return;
        }
        int iIntValue = ((Integer) list.get(i2)).intValue();
        if (iIntValue == 0) {
            zzox zzoxVarZza = zzpjVar.zza();
            zzpd zzpdVar = (zzpd) this.zza.get(zzoxVarZza.zzb());
            if (!zzpjVar.zza().zzg()) {
                if ((zzpdVar != null ? zzpdVar.zza() : this.zzc.zza(zzoxVarZza.zzb())) + 900000 >= this.zzd.currentTimeMillis()) {
                    zzb(zzpjVar, list, i2 + 1, zzpbVar, zzgoVar);
                    return;
                }
            }
            zzpv zzpvVar = (zzpv) this.zze.get(zzpjVar.zzc());
            if (zzpvVar == null) {
                zzpvVar = new zzpv();
                this.zze.put(zzpjVar.zzc(), zzpvVar);
            }
            zzhi.zzd("Attempting to fetch container " + zzoxVarZza.zzb() + " from network");
            zzpvVar.zza(this.zzb, zzpjVar, 0L, new zzpc(this, 0, zzpjVar, zzpi.zza, list, i2, zzpbVar, zzgoVar));
            return;
        }
        if (iIntValue == 1) {
            zzox zzoxVarZza2 = zzpjVar.zza();
            zzhi.zzd("Attempting to fetch container " + zzoxVarZza2.zzb() + " from a saved resource");
            this.zzc.zze(zzoxVarZza2.zzd(), new zzpc(this, 1, zzpjVar, zzpi.zza, list, i2, zzpbVar, null));
            return;
        }
        if (iIntValue != 2) {
            throw new UnsupportedOperationException(android.support.v4.media.session.a.f(i2, "Unknown fetching source: "));
        }
        zzox zzoxVarZza3 = zzpjVar.zza();
        zzhi.zzd("Attempting to fetch container " + zzoxVarZza3.zzb() + " from the default resource");
        this.zzc.zzc(zzoxVarZza3.zzd(), zzoxVarZza3.zzc(), new zzpc(this, 2, zzpjVar, zzpi.zza, list, i2, zzpbVar, null));
    }

    public final void zzc(String str, String str2, String str3, List list, zzpb zzpbVar, zzgo zzgoVar) throws IllegalArgumentException {
        u.b(!list.isEmpty());
        zzpj zzpjVar = new zzpj();
        zzhp zzhpVarZza = zzhp.zza();
        zzpjVar.zzb(new zzox(str, str2, str3, zzhpVarZza.zzd() && str.equals(zzhpVarZza.zzc()), zzhp.zza().zzb(), ""));
        zzb(zzpjVar, Collections.unmodifiableList(list), 0, zzpbVar, zzgoVar);
    }

    public final void zzd(Status status, zzpk zzpkVar) {
        String strZzb = zzpkVar.zzb().zzb();
        zzpy zzpyVarZzc = zzpkVar.zzc();
        if (this.zza.containsKey(strZzb)) {
            ((zzpd) this.zza.get(strZzb)).zzb(this.zzd.currentTimeMillis());
        } else {
            this.zza.put(strZzb, new zzpd(status, zzpyVarZzc, this.zzd.currentTimeMillis()));
        }
    }
}
