package com.skydoves.balloon;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class AutoDismissRunnable implements Runnable {

    @NotNull
    private final Balloon balloon;

    public AutoDismissRunnable(@NotNull Balloon balloon) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        this.balloon = balloon;
    }

    @NotNull
    public final Balloon getBalloon() {
        return this.balloon;
    }

    @Override // java.lang.Runnable
    public void run() {
        this.balloon.dismiss();
    }
}
