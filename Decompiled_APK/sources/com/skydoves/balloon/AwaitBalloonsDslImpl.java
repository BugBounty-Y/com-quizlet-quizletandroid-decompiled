package com.skydoves.balloon;

import android.view.View;
import com.skydoves.balloon.AwaitBalloonsDsl;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
final class AwaitBalloonsDslImpl implements AwaitBalloonsDsl {

    @NotNull
    private final List<DeferredBalloon> _balloons = new ArrayList();
    private boolean dismissSequentially;

    @Override // com.skydoves.balloon.AwaitBalloonsDsl
    public void alignBottom(@NotNull View view, @NotNull Balloon balloon, int i, int i2) {
        AwaitBalloonsDsl.DefaultImpls.alignBottom(this, view, balloon, i, i2);
    }

    @Override // com.skydoves.balloon.AwaitBalloonsDsl
    public void alignEnd(@NotNull View view, @NotNull Balloon balloon, int i, int i2) {
        AwaitBalloonsDsl.DefaultImpls.alignEnd(this, view, balloon, i, i2);
    }

    @Override // com.skydoves.balloon.AwaitBalloonsDsl
    public void alignStart(@NotNull View view, @NotNull Balloon balloon, int i, int i2) {
        AwaitBalloonsDsl.DefaultImpls.alignStart(this, view, balloon, i, i2);
    }

    @Override // com.skydoves.balloon.AwaitBalloonsDsl
    public void alignTop(@NotNull View view, @NotNull Balloon balloon, int i, int i2) {
        AwaitBalloonsDsl.DefaultImpls.alignTop(this, view, balloon, i, i2);
    }

    @Override // com.skydoves.balloon.AwaitBalloonsDsl
    public void asDropDown(@NotNull View view, @NotNull Balloon balloon, int i, int i2) {
        AwaitBalloonsDsl.DefaultImpls.asDropDown(this, view, balloon, i, i2);
    }

    @Override // com.skydoves.balloon.AwaitBalloonsDsl
    public void atCenter(@NotNull View view, @NotNull Balloon balloon, int i, int i2, @NotNull BalloonCenterAlign balloonCenterAlign) {
        AwaitBalloonsDsl.DefaultImpls.atCenter(this, view, balloon, i, i2, balloonCenterAlign);
    }

    @NotNull
    public final DeferredBalloonGroup build() {
        return new DeferredBalloonGroup(this._balloons, getDismissSequentially());
    }

    @Override // com.skydoves.balloon.AwaitBalloonsDsl
    public boolean getDismissSequentially() {
        return this.dismissSequentially;
    }

    @Override // com.skydoves.balloon.AwaitBalloonsDsl
    public void setDismissSequentially(boolean z) {
        this.dismissSequentially = z;
    }

    @Override // com.skydoves.balloon.AwaitBalloonsDsl
    public void alignBottom(@NotNull Balloon balloon, @NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloon, "<this>");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        this._balloons.add(new DeferredBalloon(balloon, new BalloonPlacement(anchor, null, BalloonAlign.BOTTOM, i, i2, null, 0, 0, 226, null)));
    }

    @Override // com.skydoves.balloon.AwaitBalloonsDsl
    public void alignEnd(@NotNull Balloon balloon, @NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloon, "<this>");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        this._balloons.add(new DeferredBalloon(balloon, new BalloonPlacement(anchor, null, BalloonAlign.END, i, i2, null, 0, 0, 226, null)));
    }

    @Override // com.skydoves.balloon.AwaitBalloonsDsl
    public void alignStart(@NotNull Balloon balloon, @NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloon, "<this>");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        this._balloons.add(new DeferredBalloon(balloon, new BalloonPlacement(anchor, null, BalloonAlign.START, i, i2, null, 0, 0, 226, null)));
    }

    @Override // com.skydoves.balloon.AwaitBalloonsDsl
    public void alignTop(@NotNull Balloon balloon, @NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloon, "<this>");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        this._balloons.add(new DeferredBalloon(balloon, new BalloonPlacement(anchor, null, BalloonAlign.TOP, i, i2, null, 0, 0, 226, null)));
    }

    @Override // com.skydoves.balloon.AwaitBalloonsDsl
    public void asDropDown(@NotNull Balloon balloon, @NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloon, "<this>");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        this._balloons.add(new DeferredBalloon(balloon, new BalloonPlacement(anchor, null, null, i, i2, PlacementType.DROPDOWN, 0, 0, 198, null)));
    }

    @Override // com.skydoves.balloon.AwaitBalloonsDsl
    public void atCenter(@NotNull Balloon balloon, @NotNull View anchor, int i, int i2, @NotNull BalloonCenterAlign centerAlign) {
        Intrinsics.checkNotNullParameter(balloon, "<this>");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        Intrinsics.checkNotNullParameter(centerAlign, "centerAlign");
        this._balloons.add(new DeferredBalloon(balloon, new BalloonPlacement(anchor, null, centerAlign.toAlign(), i, i2, PlacementType.CENTER, 0, 0, 194, null)));
    }
}
