package com.google.android.gms.tagmanager;

import java.util.Map;

/* loaded from: classes2.dex */
final class zzbj extends zzca {
    @Override // com.google.android.gms.tagmanager.zzcb
    public final String zzb(String str, Map map) {
        if (zzbk.zzd.containsKey(str)) {
            if (zzbk.zzd.get(str) == null) {
                return null;
            }
            throw new ClassCastException();
        }
        if (zzbk.zzj(str, CustomVariableProvider.class) != null) {
            throw new ClassCastException();
        }
        zzbk.zzd.put(str, null);
        return null;
    }

    @Override // com.google.android.gms.tagmanager.zzcb
    public final void zzc(String str, Map map) {
        if (zzbk.zzc.containsKey(str)) {
            if (zzbk.zzc.get(str) != null) {
                throw new ClassCastException();
            }
        } else {
            if (zzbk.zzj(str, CustomTagProvider.class) != null) {
                throw new ClassCastException();
            }
            zzbk.zzc.put(str, null);
        }
    }
}
