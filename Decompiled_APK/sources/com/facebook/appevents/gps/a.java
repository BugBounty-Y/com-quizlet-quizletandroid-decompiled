package com.facebook.appevents.gps;

import android.content.Context;
import android.os.Bundle;
import com.facebook.appevents.p;
import kotlin.jvm.internal.Intrinsics;
import kotlin.random.e;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class a {
    public static final boolean b;
    public final p a;

    static {
        e.a.getClass();
        b = e.b.b() <= 1.0E-4d;
    }

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = new p(context);
    }

    public final void a(Bundle bundle, String str) {
        if (b && StringsKt.G(str, "gps", false)) {
            this.a.b(bundle, str);
        }
    }
}
