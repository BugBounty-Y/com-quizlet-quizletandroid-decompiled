package com.google.android.gms.ads.internal.util;

import android.content.Context;
import android.os.Message;
import com.google.android.gms.internal.ads.AbstractC2086g8;
import com.google.android.gms.internal.ads.Ls;

/* loaded from: classes2.dex */
public final class B extends Ls {
    @Override // com.google.android.gms.internal.ads.Ls
    public final void a(Message message) {
        try {
            super.a(message);
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
            F f = jVar.c;
            Context context = jVar.h.e;
            if (context != null) {
                try {
                    if (((Boolean) AbstractC2086g8.b.o()).booleanValue()) {
                        com.google.android.gms.common.util.c.a(context, th);
                    }
                } catch (IllegalStateException unused) {
                }
            }
            throw th;
        }
    }

    @Override // android.os.Handler
    public final void handleMessage(Message message) {
        try {
            super.handleMessage(message);
        } catch (Exception e) {
            com.google.android.gms.ads.internal.j.C.h.h("AdMobHandler.handleMessage", e);
        }
    }
}
