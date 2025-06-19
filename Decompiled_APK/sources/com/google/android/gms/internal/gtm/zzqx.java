package com.google.android.gms.internal.gtm;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.common.internal.u;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzqx extends zzqo {
    private final String zzb;
    private final List zzc;

    public zzqx(String str, List list) {
        u.i(str, "Instruction name must be a string.");
        u.h(list);
        this.zzb = str;
        this.zzc = list;
    }

    @Override // com.google.android.gms.internal.gtm.zzqo
    /* renamed from: toString, reason: merged with bridge method [inline-methods] */
    public final String zzc() {
        return AbstractC0147y.g(new StringBuilder("*"), this.zzb, ": ", this.zzc.toString());
    }

    public final String zzi() {
        return this.zzb;
    }

    public final List zzj() {
        return this.zzc;
    }
}
