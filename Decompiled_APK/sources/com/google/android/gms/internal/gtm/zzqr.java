package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzqr extends zzqo {
    private static final Map zzb;
    private final zzjm zzc;

    static {
        HashMap map = new HashMap();
        map.put("hasOwnProperty", zzln.zza);
        zzb = Collections.unmodifiableMap(map);
    }

    public zzqr(zzjm zzjmVar) {
        this.zzc = zzjmVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    /* renamed from: toString */
    public final String zzc() {
        return this.zzc.toString();
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    public final zzjm zza(String str) {
        if (zzg(str)) {
            return (zzjm) zzb.get(str);
        }
        throw new IllegalStateException(a.B("Native Method ", str, " is not defined for type InstructionReference."));
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    public final /* synthetic */ Object zzc() {
        return this.zzc;
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    public final Iterator zze() {
        return zzd();
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    public final boolean zzg(String str) {
        return zzb.containsKey(str);
    }

    public final zzjm zzi() {
        return this.zzc;
    }
}
