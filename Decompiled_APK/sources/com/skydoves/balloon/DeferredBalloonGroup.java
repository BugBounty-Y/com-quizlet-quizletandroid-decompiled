package com.skydoves.balloon;

import com.skydoves.balloon.annotations.InternalBalloonApi;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
@InternalBalloonApi
/* loaded from: classes3.dex */
public final class DeferredBalloonGroup {

    @NotNull
    private final List<DeferredBalloon> balloons;
    private final boolean dismissSequentially;

    public DeferredBalloonGroup(@NotNull List<DeferredBalloon> balloons, boolean z) {
        Intrinsics.checkNotNullParameter(balloons, "balloons");
        this.balloons = balloons;
        this.dismissSequentially = z;
    }

    @NotNull
    public final List<DeferredBalloon> getBalloons() {
        return this.balloons;
    }

    public final boolean getDismissSequentially() {
        return this.dismissSequentially;
    }
}
