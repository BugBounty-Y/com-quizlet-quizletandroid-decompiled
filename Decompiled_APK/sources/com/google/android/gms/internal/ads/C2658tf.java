package com.google.android.gms.internal.ads;

import android.content.Context;
import java.io.IOException;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.tf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2658tf implements InterfaceC2315lf {
    public final Context a;
    public final com.google.android.gms.ads.internal.util.C b = com.google.android.gms.ads.internal.j.C.h.d();

    public C2658tf(Context context) {
        this.a = context;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2315lf
    public final void a(HashMap map) throws IOException {
        String str;
        if (map.isEmpty() || (str = (String) map.get("gad_idless")) == null) {
            return;
        }
        boolean z = Boolean.parseBoolean(str);
        this.b.c(z);
        if (z) {
            com.google.android.gms.internal.mlkit_vision_common.U2.e(this.a);
        }
    }
}
