package com.skydoves.balloon.overlay;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes3.dex */
public final class BalloonOverlayAnimation {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ BalloonOverlayAnimation[] $VALUES;
    public static final BalloonOverlayAnimation NONE = new BalloonOverlayAnimation("NONE", 0);
    public static final BalloonOverlayAnimation FADE = new BalloonOverlayAnimation("FADE", 1);

    private static final /* synthetic */ BalloonOverlayAnimation[] $values() {
        return new BalloonOverlayAnimation[]{NONE, FADE};
    }

    static {
        BalloonOverlayAnimation[] balloonOverlayAnimationArr$values = $values();
        $VALUES = balloonOverlayAnimationArr$values;
        $ENTRIES = AbstractC3328d.f(balloonOverlayAnimationArr$values);
    }

    private BalloonOverlayAnimation(String str, int i) {
    }

    @NotNull
    public static a getEntries() {
        return $ENTRIES;
    }

    public static BalloonOverlayAnimation valueOf(String str) {
        return (BalloonOverlayAnimation) Enum.valueOf(BalloonOverlayAnimation.class, str);
    }

    public static BalloonOverlayAnimation[] values() {
        return (BalloonOverlayAnimation[]) $VALUES.clone();
    }
}
