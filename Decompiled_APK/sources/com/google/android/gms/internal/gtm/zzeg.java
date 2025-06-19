package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
public final class zzeg {
    private final Object zza;
    private final Object zzb = new Object();

    private zzeg(Object obj, Object obj2, zzef zzefVar) {
        this.zza = obj;
    }

    public static zzeg zza(Object obj, Object obj2, zzef zzefVar) {
        return new zzeg(obj, obj2, zzefVar);
    }

    public final Object zzb() {
        synchronized (this.zzb) {
        }
        return this.zza;
    }
}
