package com.skydoves.balloon.overlay;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;

@Metadata
/* loaded from: classes3.dex */
public final class BalloonOverlayCircle extends BalloonOverlayShape {
    private final Float radius;
    private final Integer radiusRes;

    public /* synthetic */ BalloonOverlayCircle(Float f, Integer num, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : f, (i & 2) != 0 ? null : num);
    }

    public final Float getRadius() {
        return this.radius;
    }

    public final Integer getRadiusRes() {
        return this.radiusRes;
    }

    private BalloonOverlayCircle(Float f, Integer num) {
        super(null);
        this.radius = f;
        this.radiusRes = num;
    }

    public BalloonOverlayCircle(float f) {
        this(Float.valueOf(f), null);
    }

    public BalloonOverlayCircle(int i) {
        this(null, Integer.valueOf(i));
    }
}
