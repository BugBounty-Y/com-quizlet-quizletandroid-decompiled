package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zztk extends zztl {
    final transient int zza;
    final transient int zzb;
    final /* synthetic */ zztl zzc;

    public zztk(zztl zztlVar, int i, int i2) {
        this.zzc = zztlVar;
        this.zza = i;
        this.zzb = i2;
    }

    @Override // java.util.List
    public final Object get(int i) {
        zztd.zza(i, this.zzb, "index");
        return this.zzc.get(i + this.zza);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.zzb;
    }

    @Override // com.google.android.gms.internal.gtm.zzti
    public final int zzb() {
        return this.zzc.zzc() + this.zza + this.zzb;
    }

    @Override // com.google.android.gms.internal.gtm.zzti
    public final int zzc() {
        return this.zzc.zzc() + this.zza;
    }

    @Override // com.google.android.gms.internal.gtm.zzti
    public final Object[] zze() {
        return this.zzc.zze();
    }

    @Override // com.google.android.gms.internal.gtm.zztl, java.util.List
    /* renamed from: zzf, reason: merged with bridge method [inline-methods] */
    public final zztl subList(int i, int i2) {
        zztd.zzc(i, i2, this.zzb);
        int i3 = this.zza;
        return this.zzc.subList(i + i3, i2 + i3);
    }
}
