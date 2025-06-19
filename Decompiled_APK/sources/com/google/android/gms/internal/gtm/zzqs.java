package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzqs extends zzqo {
    public static final zzqs zzb = new zzqs("BREAK");
    public static final zzqs zzc = new zzqs("CONTINUE");
    public static final zzqs zzd = new zzqs("NULL");
    public static final zzqs zze = new zzqs("UNDEFINED");
    private final String zzf;
    private final boolean zzg;
    private final zzqo zzh;

    private zzqs(String str) {
        this.zzf = str;
        this.zzg = false;
        this.zzh = null;
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    /* renamed from: toString */
    public final String zzc() {
        return this.zzf;
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    public final /* synthetic */ Object zzc() {
        return this.zzh;
    }

    public final zzqo zzi() {
        return this.zzh;
    }

    public final boolean zzj() {
        return this.zzg;
    }

    public zzqs(zzqo zzqoVar) {
        u.h(zzqoVar);
        this.zzf = "RETURN";
        this.zzg = true;
        this.zzh = zzqoVar;
    }
}
