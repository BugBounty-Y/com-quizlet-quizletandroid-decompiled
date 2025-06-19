package com.facebook.appevents;

import android.content.Context;
import android.os.Bundle;
import com.facebook.B;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class p {
    public final j a;

    public p(j loggerImpl) {
        Intrinsics.checkNotNullParameter(loggerImpl, "loggerImpl");
        this.a = loggerImpl;
    }

    public final void a(String str, double d, Bundle bundle) {
        com.facebook.o oVar = com.facebook.o.a;
        if (B.c()) {
            j jVar = this.a;
            jVar.getClass();
            if (com.facebook.internal.instrument.crashshield.a.b(jVar)) {
                return;
            }
            try {
                j.f(jVar, str, Double.valueOf(d), bundle, false, com.facebook.appevents.internal.c.b());
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(jVar, th);
            }
        }
    }

    public final void b(Bundle bundle, String str) {
        com.facebook.o oVar = com.facebook.o.a;
        if (B.c()) {
            this.a.g(bundle, str);
        }
    }

    public p(Context context) {
        this(new j(context, (String) null));
    }

    public p(Context context, String str) {
        this(new j(context, str));
    }
}
