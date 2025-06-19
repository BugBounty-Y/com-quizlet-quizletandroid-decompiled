package com.google.ads.conversiontracking;

import android.content.Context;
import android.util.Log;
import com.google.android.gms.internal.mlkit_vision_common.O2;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public class f extends O2 {
    public final Context a;

    public f(Context context) {
        this.a = context;
    }

    public final void c(String str, long j) {
        try {
            Context context = this.a;
            q qVar = new q();
            qVar.a = str;
            qVar.b = true;
            qVar.h = true;
            qVar.g = TimeUnit.MILLISECONDS.toSeconds(j);
            new Thread(new b(context, qVar, false, true, true)).start();
        } catch (Exception e) {
            Log.e("GoogleConversionReporter", "Error sending ping", e);
        }
    }
}
