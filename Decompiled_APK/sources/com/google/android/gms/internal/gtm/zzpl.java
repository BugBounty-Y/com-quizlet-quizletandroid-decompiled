package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.k;

/* loaded from: classes2.dex */
public final class zzpl implements k {
    private final Status zza;
    private final int zzb;
    private final zzpk zzc;
    private final zzqh zzd;

    public zzpl(Status status, int i, zzpk zzpkVar, zzqh zzqhVar) {
        this.zza = status;
        this.zzb = i;
        this.zzc = zzpkVar;
        this.zzd = zzqhVar;
    }

    @Override // com.google.android.gms.common.api.k
    public final Status getStatus() {
        return this.zza;
    }

    public final int zza() {
        return this.zzb;
    }

    public final zzpk zzb() {
        return this.zzc;
    }

    public final zzqh zzc() {
        return this.zzd;
    }

    public final String zzd() {
        int i = this.zzb;
        if (i == 0) {
            return "Network";
        }
        if (i == 1) {
            return "Saved file on disk";
        }
        if (i == 2) {
            return "Default resource";
        }
        throw new IllegalStateException("Resource source is unknown.");
    }
}
