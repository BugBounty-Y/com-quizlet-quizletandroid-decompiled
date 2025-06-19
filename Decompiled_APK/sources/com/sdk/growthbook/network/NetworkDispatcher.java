package com.sdk.growthbook.network;

import java.util.Map;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlinx.coroutines.InterfaceC5025j0;
import kotlinx.coroutines.flow.InterfaceC4992i;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface NetworkDispatcher {
    @NotNull
    InterfaceC5025j0 consumeGETRequest(@NotNull String str, @NotNull Function1<? super String, Unit> function1, @NotNull Function1<? super Throwable, Unit> function12);

    void consumePOSTRequest(@NotNull String str, @NotNull Map<String, ? extends Object> map, @NotNull Function1<? super String, Unit> function1, @NotNull Function1<? super Throwable, Unit> function12);

    @NotNull
    InterfaceC4992i consumeSSEConnection(@NotNull String str);
}
