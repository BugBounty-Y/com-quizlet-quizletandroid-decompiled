package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;
import com.google.android.gms.common.internal.u;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzqp extends zzqo {
    private static final Map zzb;
    private final Boolean zzc;

    static {
        HashMap map = new HashMap();
        map.put("hasOwnProperty", zzln.zza);
        map.put("toString", new zzmp());
        zzb = Collections.unmodifiableMap(map);
    }

    public zzqp(Boolean bool) {
        u.h(bool);
        this.zzc = bool;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof zzqp) {
            return ((zzqp) obj).zzc.equals(this.zzc);
        }
        return false;
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
        throw new IllegalStateException(a.B("Native Method ", str, " is not defined for type BooleanWrapper."));
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    public final /* synthetic */ Object zzc() {
        return this.zzc;
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    public final boolean zzg(String str) {
        return zzb.containsKey(str);
    }

    public final Boolean zzi() {
        return this.zzc;
    }
}
