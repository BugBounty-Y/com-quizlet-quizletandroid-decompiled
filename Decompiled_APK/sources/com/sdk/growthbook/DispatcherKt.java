package com.sdk.growthbook;

import kotlin.Metadata;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.O;
import kotlinx.coroutines.scheduling.d;
import kotlinx.coroutines.scheduling.e;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class DispatcherKt {

    @NotNull
    private static final AbstractC5040y PlatformDependentIODispatcher;

    static {
        e eVar = O.a;
        PlatformDependentIODispatcher = d.b;
    }

    @NotNull
    public static final AbstractC5040y getPlatformDependentIODispatcher() {
        return PlatformDependentIODispatcher;
    }
}
