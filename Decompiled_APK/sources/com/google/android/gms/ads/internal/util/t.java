package com.google.android.gms.ads.internal.util;

import android.content.Context;
import androidx.compose.animation.core.J0;
import com.google.android.gms.internal.ads.AbstractC2025es;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.C2499pr;
import java.util.concurrent.RejectedExecutionException;

/* loaded from: classes2.dex */
public final class t extends J0 {
    public final com.google.android.gms.ads.internal.util.client.k c;
    public final String d;
    public final com.google.android.gms.auth.api.signin.internal.h e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(Context context, String str, String str2, com.google.android.gms.auth.api.signin.internal.h hVar) {
        super(5);
        String strY = com.google.android.gms.ads.internal.j.C.c.y(context, str);
        this.c = new com.google.android.gms.ads.internal.util.client.k(strY);
        this.d = str2;
        this.e = hVar;
    }

    @Override // androidx.compose.animation.core.J0
    public final void Q() {
        String str = this.d;
        com.google.android.gms.ads.internal.util.client.k kVar = this.c;
        com.google.android.gms.auth.api.signin.internal.h hVar = this.e;
        if (hVar == null) {
            kVar.zza(str);
            return;
        }
        try {
            new com.google.firebase.messaging.u((com.google.android.gms.ads.internal.util.client.h) hVar.b, kVar, AbstractC2270kd.e, (C2499pr) null).k(1, 0L, str);
        } catch (NullPointerException | RejectedExecutionException unused) {
            AbstractC2025es.E(com.google.android.gms.ads.internal.util.client.j.b);
        }
    }
}
