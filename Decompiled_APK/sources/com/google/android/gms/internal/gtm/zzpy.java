package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzpy {
    private final List zza;
    private final Map zzb;
    private final String zzc;

    public zzpy(List list, Map map, String str, int i) {
        this.zza = Collections.unmodifiableList(list);
        this.zzb = Collections.unmodifiableMap(map);
        this.zzc = str;
    }

    public final String toString() {
        return a.m("Rules: ", String.valueOf(this.zza), "\n  Macros: ", String.valueOf(this.zzb));
    }

    public final zzqb zza(String str) {
        return (zzqb) this.zzb.get(str);
    }

    public final String zzb() {
        return this.zzc;
    }

    public final List zzc() {
        return this.zza;
    }
}
