package com.appsflyer.internal;

import androidx.glance.appwidget.protobuf.Z;
import java.lang.reflect.Field;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.q;
import kotlin.r;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class AFj1gSDK implements AFj1hSDK {
    @Override // com.appsflyer.internal.AFj1hSDK
    @NotNull
    public final String getRevenue() {
        Object objB;
        try {
            p pVar = r.b;
            Field declaredField = com.android.billingclient.a.class.getDeclaredField("a");
            declaredField.setAccessible(true);
            Object obj = declaredField.get(null);
            Intrinsics.e(obj, "");
            objB = (String) obj;
        } catch (Throwable th) {
            p pVar2 = r.b;
            objB = Z.b(th);
        }
        return (String) (objB instanceof q ? "" : objB);
    }
}
