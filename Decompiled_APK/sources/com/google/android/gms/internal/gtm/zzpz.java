package com.google.android.gms.internal.gtm;

import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzpz {
    private final Map zza = new HashMap();
    private zzqk zzb;

    public final zzpz zza(String str, zzqk zzqkVar) {
        this.zza.put(str, zzqkVar);
        return this;
    }

    public final zzpz zzb(zzqk zzqkVar) {
        this.zzb = zzqkVar;
        return this;
    }

    public final zzqb zzc() {
        return new zzqb(this.zza, this.zzb, null);
    }
}
