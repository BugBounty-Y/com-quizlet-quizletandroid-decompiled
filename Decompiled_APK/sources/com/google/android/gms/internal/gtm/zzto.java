package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;
import java.io.Serializable;
import java.util.Map;
import java.util.Set;

/* loaded from: classes2.dex */
public abstract class zzto implements Map, Serializable {
    private transient zztp zza;
    private transient zztp zzb;
    private transient zzti zzc;

    public static zzto zzc(Object obj, Object obj2, Object obj3, Object obj4, Object obj5, Object obj6, Object obj7, Object obj8, Object obj9, Object obj10, Object obj11, Object obj12) {
        zztg.zza(obj, obj2);
        zztg.zza(obj3, obj4);
        zztg.zza(obj5, obj6);
        zztg.zza(obj7, obj8);
        zztg.zza(obj9, obj10);
        zztg.zza(obj11, "&cu");
        return zztw.zzg(6, new Object[]{obj, obj2, obj3, obj4, obj5, obj6, obj7, obj8, obj9, obj10, obj11, "&cu"}, null);
    }

    @Override // java.util.Map
    @Deprecated
    public final void clear() {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.Map
    public final boolean containsKey(Object obj) {
        return get(obj) != null;
    }

    @Override // java.util.Map
    public final boolean containsValue(Object obj) {
        return values().contains(obj);
    }

    @Override // java.util.Map
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Map) {
            return entrySet().equals(((Map) obj).entrySet());
        }
        return false;
    }

    @Override // java.util.Map
    public abstract Object get(Object obj);

    @Override // java.util.Map
    public final Object getOrDefault(Object obj, Object obj2) {
        Object obj3 = get(obj);
        return obj3 != null ? obj3 : obj2;
    }

    @Override // java.util.Map
    public final int hashCode() {
        return zzty.zza(entrySet());
    }

    @Override // java.util.Map
    public final boolean isEmpty() {
        return false;
    }

    @Override // java.util.Map
    public final /* bridge */ /* synthetic */ Set keySet() {
        zztp zztpVar = this.zzb;
        if (zztpVar != null) {
            return zztpVar;
        }
        zztp zztpVarZze = zze();
        this.zzb = zztpVarZze;
        return zztpVarZze;
    }

    @Override // java.util.Map
    @Deprecated
    public final Object put(Object obj, Object obj2) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.Map
    @Deprecated
    public final void putAll(Map map) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.Map
    @Deprecated
    public final Object remove(Object obj) {
        throw new UnsupportedOperationException();
    }

    public final String toString() {
        int size = size();
        if (size < 0) {
            throw new IllegalArgumentException(a.f(size, "size cannot be negative but was: "));
        }
        StringBuilder sb = new StringBuilder((int) Math.min(size * 8, 1073741824L));
        sb.append('{');
        boolean z = true;
        for (Map.Entry entry : entrySet()) {
            if (!z) {
                sb.append(", ");
            }
            sb.append(entry.getKey());
            sb.append('=');
            sb.append(entry.getValue());
            z = false;
        }
        sb.append('}');
        return sb.toString();
    }

    public abstract zzti zza();

    @Override // java.util.Map
    /* renamed from: zzb, reason: merged with bridge method [inline-methods] */
    public final zzti values() {
        zzti zztiVar = this.zzc;
        if (zztiVar != null) {
            return zztiVar;
        }
        zzti zztiVarZza = zza();
        this.zzc = zztiVarZza;
        return zztiVarZza;
    }

    public abstract zztp zzd();

    public abstract zztp zze();

    @Override // java.util.Map
    /* renamed from: zzf, reason: merged with bridge method [inline-methods] */
    public final zztp entrySet() {
        zztp zztpVar = this.zza;
        if (zztpVar != null) {
            return zztpVar;
        }
        zztp zztpVarZzd = zzd();
        this.zza = zztpVarZzd;
        return zztpVarZzd;
    }
}
