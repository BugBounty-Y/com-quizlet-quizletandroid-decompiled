package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;
import com.google.android.gms.common.internal.u;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzqw extends zzqo {
    private static final Map zzb;
    private boolean zzc = false;

    static {
        HashMap map = new HashMap();
        map.put("hasOwnProperty", zzln.zza);
        zzb = Collections.unmodifiableMap(map);
    }

    public zzqw(Map map) {
        u.h(map);
        this.zza = map;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof zzqw) {
            return this.zza.entrySet().equals(((zzqw) obj).zza.entrySet());
        }
        return false;
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    /* renamed from: toString */
    public final String zzc() {
        return this.zza.toString();
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    public final zzjm zza(String str) {
        if (zzg(str)) {
            return (zzjm) zzb.get(str);
        }
        throw new IllegalStateException(a.B("Native Method ", str, " is not defined for type ListWrapper."));
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    public final zzqo zzb(String str) {
        zzqo zzqoVarZzb = super.zzb(str);
        return zzqoVarZzb == null ? zzqs.zze : zzqoVarZzb;
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    public final /* synthetic */ Object zzc() {
        return this.zza;
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    public final Iterator zze() {
        return zzd();
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    public final boolean zzg(String str) {
        return zzb.containsKey(str);
    }

    public final Map zzi() {
        return this.zza;
    }

    public final void zzj() {
        this.zzc = true;
    }

    public final boolean zzk() {
        return this.zzc;
    }
}
