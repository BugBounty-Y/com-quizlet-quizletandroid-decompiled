package com.skydoves.balloon.compose;

import com.skydoves.balloon.BalloonAlign;
import com.skydoves.balloon.BalloonCenterAlign;
import com.skydoves.balloon.BalloonPlacement;
import com.skydoves.balloon.DeferredBalloon;
import com.skydoves.balloon.DeferredBalloonGroup;
import com.skydoves.balloon.PlacementType;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
final class AwaitBalloonWindowsDslImpl implements AwaitBalloonWindowsDsl {

    @NotNull
    private final List<DeferredBalloon> _balloons = new ArrayList();
    private boolean dismissSequentially;

    @Override // com.skydoves.balloon.compose.AwaitBalloonWindowsDsl
    public void alignBottom(@NotNull BalloonWindow balloonWindow, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloonWindow, "<this>");
        this._balloons.add(new DeferredBalloon(balloonWindow.getBalloon(), new BalloonPlacement(balloonWindow.getAnchorView(), null, BalloonAlign.BOTTOM, i, i2, null, 0, 0, 226, null)));
    }

    @Override // com.skydoves.balloon.compose.AwaitBalloonWindowsDsl
    public void alignEnd(@NotNull BalloonWindow balloonWindow, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloonWindow, "<this>");
        this._balloons.add(new DeferredBalloon(balloonWindow.getBalloon(), new BalloonPlacement(balloonWindow.getAnchorView(), null, BalloonAlign.END, i, i2, null, 0, 0, 226, null)));
    }

    @Override // com.skydoves.balloon.compose.AwaitBalloonWindowsDsl
    public void alignStart(@NotNull BalloonWindow balloonWindow, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloonWindow, "<this>");
        this._balloons.add(new DeferredBalloon(balloonWindow.getBalloon(), new BalloonPlacement(balloonWindow.getAnchorView(), null, BalloonAlign.START, i, i2, null, 0, 0, 226, null)));
    }

    @Override // com.skydoves.balloon.compose.AwaitBalloonWindowsDsl
    public void alignTop(@NotNull BalloonWindow balloonWindow, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloonWindow, "<this>");
        this._balloons.add(new DeferredBalloon(balloonWindow.getBalloon(), new BalloonPlacement(balloonWindow.getAnchorView(), null, BalloonAlign.TOP, i, i2, null, 0, 0, 226, null)));
    }

    @Override // com.skydoves.balloon.compose.AwaitBalloonWindowsDsl
    public void asDropDown(@NotNull BalloonWindow balloonWindow, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloonWindow, "<this>");
        this._balloons.add(new DeferredBalloon(balloonWindow.getBalloon(), new BalloonPlacement(balloonWindow.getAnchorView(), null, null, i, i2, PlacementType.DROPDOWN, 0, 0, 198, null)));
    }

    @Override // com.skydoves.balloon.compose.AwaitBalloonWindowsDsl
    public void atCenter(@NotNull BalloonWindow balloonWindow, int i, int i2, @NotNull BalloonCenterAlign centerAlign) {
        Intrinsics.checkNotNullParameter(balloonWindow, "<this>");
        Intrinsics.checkNotNullParameter(centerAlign, "centerAlign");
        this._balloons.add(new DeferredBalloon(balloonWindow.getBalloon(), new BalloonPlacement(balloonWindow.getAnchorView(), null, centerAlign.toAlign(), i, i2, PlacementType.CENTER, 0, 0, 194, null)));
    }

    @NotNull
    public final DeferredBalloonGroup build() {
        return new DeferredBalloonGroup(this._balloons, getDismissSequentially());
    }

    @Override // com.skydoves.balloon.compose.AwaitBalloonWindowsDsl
    public boolean getDismissSequentially() {
        return this.dismissSequentially;
    }

    @Override // com.skydoves.balloon.compose.AwaitBalloonWindowsDsl
    public void setDismissSequentially(boolean z) {
        this.dismissSequentially = z;
    }
}
