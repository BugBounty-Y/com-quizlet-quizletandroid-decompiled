package com.google.android.gms.ads.internal.util;

import android.content.Context;
import com.google.android.gms.ads.internal.client.AbstractBinderC1601j0;
import com.google.android.gms.ads.internal.client.zze;

/* renamed from: com.google.android.gms.ads.internal.util.j, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC1634j extends AbstractBinderC1601j0 {
    public final /* synthetic */ Context a;
    public final /* synthetic */ androidx.camera.camera2.interop.c b;

    public BinderC1634j(androidx.camera.camera2.interop.c cVar, Context context) {
        this.a = context;
        this.b = cVar;
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1603k0
    public final void T1(zze zzeVar) {
        if (zzeVar == null) {
            return;
        }
        this.b.getClass();
        androidx.camera.camera2.interop.c.e(this.a, zzeVar.b, true, true);
    }
}
