package com.braze.requests;

import com.braze.AbstractC1484j;
import com.braze.managers.C;
import com.braze.support.BrazeLogger;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class l {
    public static final String b(String str) {
        return AbstractC1484j.a("No RequestEndpointDestination found for name: ", str);
    }

    public final m a(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        try {
            return m.valueOf(name);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new C(name, 27), 4, (Object) null);
            return null;
        }
    }
}
