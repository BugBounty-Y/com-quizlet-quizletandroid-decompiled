package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzpj {
    private zzox zza;

    public final zzox zza() {
        return this.zza;
    }

    public final zzpj zzb(zzox zzoxVar) throws IllegalArgumentException {
        u.h(zzoxVar);
        this.zza = zzoxVar;
        return this;
    }

    public final String zzc() {
        zzox zzoxVar = this.zza;
        return zzoxVar == null ? "" : zzoxVar.zzb();
    }
}
