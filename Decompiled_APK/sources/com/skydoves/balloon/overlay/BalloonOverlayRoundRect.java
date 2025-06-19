package com.skydoves.balloon.overlay;

import kotlin.Metadata;
import kotlin.Pair;
import kotlin.jvm.internal.DefaultConstructorMarker;

@Metadata
/* loaded from: classes3.dex */
public final class BalloonOverlayRoundRect extends BalloonOverlayShape {
    private final Pair<Float, Float> radiusPair;
    private final Pair<Integer, Integer> radiusResPair;

    public /* synthetic */ BalloonOverlayRoundRect(Pair pair, Pair pair2, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((Pair<Float, Float>) ((i & 1) != 0 ? null : pair), (Pair<Integer, Integer>) ((i & 2) != 0 ? null : pair2));
    }

    public final Pair<Float, Float> getRadiusPair() {
        return this.radiusPair;
    }

    public final Pair<Integer, Integer> getRadiusResPair() {
        return this.radiusResPair;
    }

    private BalloonOverlayRoundRect(Pair<Float, Float> pair, Pair<Integer, Integer> pair2) {
        super(null);
        this.radiusPair = pair;
        this.radiusResPair = pair2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public BalloonOverlayRoundRect(float f, float f2) {
        this(new Pair(Float.valueOf(f), Float.valueOf(f2)), null, 2, 0 == true ? 1 : 0);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public BalloonOverlayRoundRect(int i, int i2) {
        this(null, new Pair(Integer.valueOf(i), Integer.valueOf(i2)), 1, 0 == true ? 1 : 0);
    }
}
