package com.skydoves.balloon.extensions;

import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class GlobalExtensionKt {
    public static final /* synthetic */ boolean isAPILevelHigherThan23() {
        return true;
    }

    public static final /* synthetic */ void runOnAfterSDK22(Function0<Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        block.invoke();
    }

    public static final /* synthetic */ void runOnAfterSDK23(Function0<Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        block.invoke();
    }
}
