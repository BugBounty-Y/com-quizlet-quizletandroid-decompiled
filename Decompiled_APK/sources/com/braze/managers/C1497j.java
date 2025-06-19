package com.braze.managers;

import com.braze.C1480f;
import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.enums.LocationProviderName;
import com.braze.support.BrazeLogger;
import java.util.EnumSet;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.braze.managers.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1497j {
    public final EnumSet a(BrazeConfigurationProvider appConfigurationProvider) {
        Intrinsics.checkNotNullParameter(appConfigurationProvider, "appConfigurationProvider");
        kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
        j.a = EnumSet.of(LocationProviderName.PASSIVE, LocationProviderName.NETWORK);
        if (!appConfigurationProvider.getCustomLocationProviderNames().isEmpty()) {
            j.a = appConfigurationProvider.getCustomLocationProviderNames();
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new C1480f(j, 6), 6, (Object) null);
        }
        Object element = j.a;
        Intrinsics.checkNotNullExpressionValue(element, "element");
        return (EnumSet) element;
    }

    public static final String a(kotlin.jvm.internal.J j) {
        return "Using location providers: " + j.a;
    }
}
