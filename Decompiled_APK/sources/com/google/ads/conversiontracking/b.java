package com.google.ads.conversiontracking;

import android.content.Context;
import android.util.Log;

/* loaded from: classes2.dex */
public final class b implements Runnable {
    public final /* synthetic */ Context a;
    public final /* synthetic */ q b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ boolean e;

    public b(Context context, q qVar, boolean z, boolean z2, boolean z3) {
        this.a = context;
        this.b = qVar;
        this.c = z;
        this.d = z2;
        this.e = z3;
    }

    @Override // java.lang.Runnable
    public final void run() {
        l lVar;
        try {
            String strB = r.b(this.a, this.b);
            if (strB != null) {
                Context context = this.a;
                synchronized (r.b) {
                    try {
                        if (r.c == null) {
                            r.c = new l(context);
                        }
                        lVar = r.c;
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                lVar.b(strB, this.b, this.c, this.d, this.e);
            }
        } catch (Exception e) {
            Log.e("GoogleConversionReporter", "Error sending ping", e);
        }
    }
}
