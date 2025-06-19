package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Looper;

/* renamed from: com.google.android.gms.internal.ads.rs, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2585rs {
    public final Context a;
    public final Looper b;

    public C2585rs(Context context, Looper looper) {
        this.a = context;
        this.b = looper;
    }

    public final void a(String str) {
        C2757vs c2757vsW = C2800ws.w();
        Context context = this.a;
        String packageName = context.getPackageName();
        c2757vsW.e();
        C2800ws.x((C2800ws) c2757vsW.b, packageName);
        c2757vsW.e();
        C2800ws.z((C2800ws) c2757vsW.b);
        C2671ts c2671tsW = C2714us.w();
        c2671tsW.e();
        C2714us.x((C2714us) c2671tsW.b, str);
        c2671tsW.e();
        C2714us.y((C2714us) c2671tsW.b);
        c2757vsW.e();
        C2800ws.y((C2800ws) c2757vsW.b, (C2714us) c2671tsW.c());
        androidx.camera.camera2.internal.m0 m0Var = new androidx.camera.camera2.internal.m0(context, this.b, (C2800ws) c2757vsW.c());
        synchronized (m0Var.e) {
            try {
                if (!m0Var.a) {
                    m0Var.a = true;
                    ((C2886ys) m0Var.c).c();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
