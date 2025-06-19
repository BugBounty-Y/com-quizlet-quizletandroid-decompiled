package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zztj extends zztf {
    private final zztl zza;

    public zztj(zztl zztlVar, int i) {
        super(zztlVar.size(), i);
        this.zza = zztlVar;
    }

    @Override // com.google.android.gms.internal.gtm.zztf
    public final Object zza(int i) {
        return this.zza.get(i);
    }
}
