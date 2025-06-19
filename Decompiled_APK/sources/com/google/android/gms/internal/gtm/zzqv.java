package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;
import com.google.android.gms.common.internal.u;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzqv extends zzqo {
    private static final Map zzb;
    private final ArrayList zzc;

    static {
        HashMap map = new HashMap();
        map.put("concat", new zzjp());
        map.put("every", new zzjq());
        map.put("filter", new zzjr());
        map.put("forEach", new zzjs());
        map.put("indexOf", new zzjt());
        map.put("hasOwnProperty", zzln.zza);
        map.put("join", new zzju());
        map.put("lastIndexOf", new zzjv());
        map.put("map", new zzjw());
        map.put("pop", new zzjx());
        map.put("push", new zzjy());
        map.put("reduce", new zzjz());
        map.put("reduceRight", new zzka());
        map.put("reverse", new zzkb());
        map.put("shift", new zzkc());
        map.put("slice", new zzkd());
        map.put("some", new zzke());
        map.put("sort", new zzki());
        map.put("splice", new zzkj());
        map.put("toString", new zzmp());
        map.put("unshift", new zzkk());
        zzb = Collections.unmodifiableMap(map);
    }

    public zzqv(List list) {
        u.h(list);
        this.zzc = new ArrayList(list);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof zzqv)) {
            return false;
        }
        ArrayList arrayList = ((zzqv) obj).zzc;
        if (this.zzc.size() != arrayList.size()) {
            return false;
        }
        boolean zEquals = true;
        for (int i = 0; i < this.zzc.size(); i++) {
            zEquals = this.zzc.get(i) == null ? arrayList.get(i) == null : ((zzqo) this.zzc.get(i)).equals(arrayList.get(i));
            if (!zEquals) {
                return zEquals;
            }
        }
        return zEquals;
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
        return new zzqu(this, new zzqt(this), zzd());
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    public final boolean zzg(String str) {
        return zzb.containsKey(str);
    }

    public final zzqo zzi(int i) {
        zzqo zzqoVar;
        return (i < 0 || i >= this.zzc.size() || (zzqoVar = (zzqo) this.zzc.get(i)) == null) ? zzqs.zze : zzqoVar;
    }

    public final List zzk() {
        return this.zzc;
    }

    public final void zzl(int i, zzqo zzqoVar) {
        if (i < 0) {
            throw new IndexOutOfBoundsException();
        }
        if (i >= this.zzc.size()) {
            zzm(i + 1);
        }
        this.zzc.set(i, zzqoVar);
    }

    public final void zzm(int i) {
        u.a("Invalid array length", i >= 0);
        if (this.zzc.size() == i) {
            return;
        }
        if (this.zzc.size() >= i) {
            ArrayList arrayList = this.zzc;
            arrayList.subList(i, arrayList.size()).clear();
            return;
        }
        this.zzc.ensureCapacity(i);
        for (int size = this.zzc.size(); size < i; size++) {
            this.zzc.add(null);
        }
    }

    public final boolean zzn(int i) {
        return i >= 0 && i < this.zzc.size() && this.zzc.get(i) != null;
    }
}
