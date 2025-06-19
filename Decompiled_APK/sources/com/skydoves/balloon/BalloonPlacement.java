package com.skydoves.balloon;

import android.view.View;
import androidx.compose.animation.d0;
import com.skydoves.balloon.annotations.InternalBalloonApi;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
@InternalBalloonApi
/* loaded from: classes3.dex */
public final class BalloonPlacement {

    @NotNull
    private final BalloonAlign align;

    @NotNull
    private final View anchor;
    private final int height;

    @NotNull
    private final List<View> subAnchors;

    @NotNull
    private final PlacementType type;
    private final int width;
    private final int xOff;
    private final int yOff;

    /* JADX WARN: Multi-variable type inference failed */
    public BalloonPlacement(@NotNull View anchor, @NotNull List<? extends View> subAnchors, @NotNull BalloonAlign align, int i, int i2, @NotNull PlacementType type, int i3, int i4) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        Intrinsics.checkNotNullParameter(subAnchors, "subAnchors");
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(type, "type");
        this.anchor = anchor;
        this.subAnchors = subAnchors;
        this.align = align;
        this.xOff = i;
        this.yOff = i2;
        this.type = type;
        this.width = i3;
        this.height = i4;
    }

    public static /* synthetic */ BalloonPlacement copy$default(BalloonPlacement balloonPlacement, View view, List list, BalloonAlign balloonAlign, int i, int i2, PlacementType placementType, int i3, int i4, int i5, Object obj) {
        if ((i5 & 1) != 0) {
            view = balloonPlacement.anchor;
        }
        if ((i5 & 2) != 0) {
            list = balloonPlacement.subAnchors;
        }
        if ((i5 & 4) != 0) {
            balloonAlign = balloonPlacement.align;
        }
        if ((i5 & 8) != 0) {
            i = balloonPlacement.xOff;
        }
        if ((i5 & 16) != 0) {
            i2 = balloonPlacement.yOff;
        }
        if ((i5 & 32) != 0) {
            placementType = balloonPlacement.type;
        }
        if ((i5 & 64) != 0) {
            i3 = balloonPlacement.width;
        }
        if ((i5 & 128) != 0) {
            i4 = balloonPlacement.height;
        }
        int i6 = i3;
        int i7 = i4;
        int i8 = i2;
        PlacementType placementType2 = placementType;
        return balloonPlacement.copy(view, list, balloonAlign, i, i8, placementType2, i6, i7);
    }

    @NotNull
    public final View component1() {
        return this.anchor;
    }

    @NotNull
    public final List<View> component2() {
        return this.subAnchors;
    }

    @NotNull
    public final BalloonAlign component3() {
        return this.align;
    }

    public final int component4() {
        return this.xOff;
    }

    public final int component5() {
        return this.yOff;
    }

    @NotNull
    public final PlacementType component6() {
        return this.type;
    }

    public final int component7() {
        return this.width;
    }

    public final int component8() {
        return this.height;
    }

    @NotNull
    public final BalloonPlacement copy(@NotNull View anchor, @NotNull List<? extends View> subAnchors, @NotNull BalloonAlign align, int i, int i2, @NotNull PlacementType type, int i3, int i4) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        Intrinsics.checkNotNullParameter(subAnchors, "subAnchors");
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(type, "type");
        return new BalloonPlacement(anchor, subAnchors, align, i, i2, type, i3, i4);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof BalloonPlacement)) {
            return false;
        }
        BalloonPlacement balloonPlacement = (BalloonPlacement) obj;
        return Intrinsics.b(this.anchor, balloonPlacement.anchor) && Intrinsics.b(this.subAnchors, balloonPlacement.subAnchors) && this.align == balloonPlacement.align && this.xOff == balloonPlacement.xOff && this.yOff == balloonPlacement.yOff && this.type == balloonPlacement.type && this.width == balloonPlacement.width && this.height == balloonPlacement.height;
    }

    @NotNull
    public final BalloonAlign getAlign() {
        return this.align;
    }

    @NotNull
    public final View getAnchor() {
        return this.anchor;
    }

    public final int getHeight() {
        return this.height;
    }

    @NotNull
    public final List<View> getSubAnchors() {
        return this.subAnchors;
    }

    @NotNull
    public final PlacementType getType() {
        return this.type;
    }

    public final int getWidth() {
        return this.width;
    }

    public final int getXOff() {
        return this.xOff;
    }

    public final int getYOff() {
        return this.yOff;
    }

    public int hashCode() {
        return Integer.hashCode(this.height) + d0.b(this.width, (this.type.hashCode() + d0.b(this.yOff, d0.b(this.xOff, (this.align.hashCode() + d0.f(this.anchor.hashCode() * 31, 31, this.subAnchors)) * 31, 31), 31)) * 31, 31);
    }

    @NotNull
    public String toString() {
        return "BalloonPlacement(anchor=" + this.anchor + ", subAnchors=" + this.subAnchors + ", align=" + this.align + ", xOff=" + this.xOff + ", yOff=" + this.yOff + ", type=" + this.type + ", width=" + this.width + ", height=" + this.height + ")";
    }

    public BalloonPlacement(View view, List list, BalloonAlign balloonAlign, int i, int i2, PlacementType placementType, int i3, int i4, int i5, DefaultConstructorMarker defaultConstructorMarker) {
        this(view, (i5 & 2) != 0 ? K.a : list, (i5 & 4) != 0 ? BalloonAlign.TOP : balloonAlign, (i5 & 8) != 0 ? 0 : i, (i5 & 16) != 0 ? 0 : i2, (i5 & 32) != 0 ? PlacementType.ALIGNMENT : placementType, (i5 & 64) != 0 ? 0 : i3, (i5 & 128) != 0 ? 0 : i4);
    }
}
