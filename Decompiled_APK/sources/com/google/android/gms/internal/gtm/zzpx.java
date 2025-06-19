package com.google.android.gms.internal.gtm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzpx {
    private final List zza = new ArrayList();
    private final Map zzb = new HashMap();
    private String zzc = "";

    public final zzpx zza(zzqb zzqbVar) {
        this.zzb.put(((zzqk) zzqbVar.zza().get("instance_name")).toString(), zzqbVar);
        return this;
    }

    public final zzpx zzb(zzqe zzqeVar) {
        this.zza.add(zzqeVar);
        return this;
    }

    public final zzpx zzc(String str) {
        this.zzc = str;
        return this;
    }

    public final zzpy zzd() {
        return new zzpy(this.zza, this.zzb, this.zzc, 0);
    }
}
