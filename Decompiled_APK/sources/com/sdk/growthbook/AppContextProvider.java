package com.sdk.growthbook;

import android.content.Context;
import androidx.startup.b;
import com.sdk.growthbook.sandbox.CachingAndroid;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class AppContextProvider implements b {
    @Override // androidx.startup.b
    @NotNull
    public List<Class<? extends b>> dependencies() {
        return K.a;
    }

    @Override // androidx.startup.b
    @NotNull
    public Context create(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        CachingAndroid.Companion.consumeContext(context);
        return context;
    }
}
