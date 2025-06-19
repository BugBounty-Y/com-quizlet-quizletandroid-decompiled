package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;
import com.google.android.gms.common.internal.u;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzqz extends zzqo {
    private static final Map zzb;
    private final String zzc;

    static {
        HashMap map = new HashMap();
        map.put("charAt", new zzmc());
        map.put("concat", new zzmd());
        map.put("hasOwnProperty", zzln.zza);
        map.put("indexOf", new zzme());
        map.put("lastIndexOf", new zzmf());
        map.put("match", new zzmg());
        map.put("replace", new zzmh());
        map.put("search", new zzmi());
        map.put("slice", new zzmj());
        map.put("split", new zzmk());
        map.put("substring", new zzml());
        map.put("toLocaleLowerCase", new zzmm());
        map.put("toLocaleUpperCase", new zzmn());
        map.put("toLowerCase", new zzmo());
        map.put("toUpperCase", new zzmq());
        map.put("toString", new zzmp());
        map.put("trim", new zzmr());
        zzb = Collections.unmodifiableMap(map);
    }

    public zzqz(String str) {
        u.h(str);
        this.zzc = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof zzqz) {
            return this.zzc.equals(((zzqz) obj).zzc);
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
        throw new IllegalStateException(a.B("Native Method ", str, " is not defined for type ListWrapper."));
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    public final /* synthetic */ Object zzc() {
        return this.zzc;
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    public final Iterator zze() {
        return new zzqy(this);
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    public final boolean zzg(String str) {
        return zzb.containsKey(str);
    }

    public final zzqo zzi(int i) {
        return (i < 0 || i >= this.zzc.length()) ? zzqs.zze : new zzqz(String.valueOf(this.zzc.charAt(i)));
    }

    public final String zzk() {
        return this.zzc;
    }
}
