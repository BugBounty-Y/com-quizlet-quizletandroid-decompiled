package com.skydoves.balloon;

import com.skydoves.balloon.annotations.InternalBalloonApi;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
@InternalBalloonApi
/* loaded from: classes3.dex */
public final class DeferredBalloon {

    @NotNull
    private final Balloon balloon;

    @NotNull
    private final BalloonPlacement placement;

    public DeferredBalloon(@NotNull Balloon balloon, @NotNull BalloonPlacement placement) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(placement, "placement");
        this.balloon = balloon;
        this.placement = placement;
    }

    public static /* synthetic */ DeferredBalloon copy$default(DeferredBalloon deferredBalloon, Balloon balloon, BalloonPlacement balloonPlacement, int i, Object obj) {
        if ((i & 1) != 0) {
            balloon = deferredBalloon.balloon;
        }
        if ((i & 2) != 0) {
            balloonPlacement = deferredBalloon.placement;
        }
        return deferredBalloon.copy(balloon, balloonPlacement);
    }

    @NotNull
    public final Balloon component1() {
        return this.balloon;
    }

    @NotNull
    public final BalloonPlacement component2() {
        return this.placement;
    }

    @NotNull
    public final DeferredBalloon copy(@NotNull Balloon balloon, @NotNull BalloonPlacement placement) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(placement, "placement");
        return new DeferredBalloon(balloon, placement);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof DeferredBalloon)) {
            return false;
        }
        DeferredBalloon deferredBalloon = (DeferredBalloon) obj;
        return Intrinsics.b(this.balloon, deferredBalloon.balloon) && Intrinsics.b(this.placement, deferredBalloon.placement);
    }

    @NotNull
    public final Balloon getBalloon() {
        return this.balloon;
    }

    @NotNull
    public final BalloonPlacement getPlacement() {
        return this.placement;
    }

    public int hashCode() {
        return this.placement.hashCode() + (this.balloon.hashCode() * 31);
    }

    @NotNull
    public String toString() {
        return "DeferredBalloon(balloon=" + this.balloon + ", placement=" + this.placement + ")";
    }
}
