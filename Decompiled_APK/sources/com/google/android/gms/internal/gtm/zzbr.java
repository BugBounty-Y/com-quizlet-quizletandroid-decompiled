package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
public abstract class zzbr extends zzbq {
    private boolean zza;

    public zzbr(zzbu zzbuVar) {
        super(zzbuVar);
    }

    public final void zzV() {
        if (!zzX()) {
            throw new IllegalStateException("Not initialized");
        }
    }

    public final void zzW() {
        zzd();
        this.zza = true;
    }

    public final boolean zzX() {
        return this.zza;
    }

    public abstract void zzd();
}
