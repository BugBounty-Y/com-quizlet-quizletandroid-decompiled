package com.skydoves.balloon;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes3.dex */
public final class BalloonAnimation {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ BalloonAnimation[] $VALUES;
    public static final BalloonAnimation NONE = new BalloonAnimation("NONE", 0);
    public static final BalloonAnimation ELASTIC = new BalloonAnimation("ELASTIC", 1);
    public static final BalloonAnimation FADE = new BalloonAnimation("FADE", 2);
    public static final BalloonAnimation CIRCULAR = new BalloonAnimation("CIRCULAR", 3);
    public static final BalloonAnimation OVERSHOOT = new BalloonAnimation("OVERSHOOT", 4);

    private static final /* synthetic */ BalloonAnimation[] $values() {
        return new BalloonAnimation[]{NONE, ELASTIC, FADE, CIRCULAR, OVERSHOOT};
    }

    static {
        BalloonAnimation[] balloonAnimationArr$values = $values();
        $VALUES = balloonAnimationArr$values;
        $ENTRIES = AbstractC3328d.f(balloonAnimationArr$values);
    }

    private BalloonAnimation(String str, int i) {
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static BalloonAnimation valueOf(String str) {
        return (BalloonAnimation) Enum.valueOf(BalloonAnimation.class, str);
    }

    public static BalloonAnimation[] values() {
        return (BalloonAnimation[]) $VALUES.clone();
    }
}
