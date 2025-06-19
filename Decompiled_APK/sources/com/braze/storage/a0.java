package com.braze.storage;

import android.content.Context;
import com.braze.C1483i;
import com.braze.support.BrazeLogger;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a0 {
    public final SharedPreferencesC1518e a;

    public a0(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = new SharedPreferencesC1518e(context);
    }

    public static final String a(boolean z) {
        return "Setting Braze SDK disabled to: " + z;
    }

    public final void b(boolean z) {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new C1483i(z, 7), 6, (Object) null);
        this.a.edit().putBoolean("appboy_sdk_disabled", z).apply();
    }
}
