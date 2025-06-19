package com.skydoves.balloon;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes3.dex */
public final class BalloonHighlightAnimation {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ BalloonHighlightAnimation[] $VALUES;
    public static final BalloonHighlightAnimation NONE = new BalloonHighlightAnimation("NONE", 0);
    public static final BalloonHighlightAnimation HEARTBEAT = new BalloonHighlightAnimation("HEARTBEAT", 1);
    public static final BalloonHighlightAnimation SHAKE = new BalloonHighlightAnimation("SHAKE", 2);
    public static final BalloonHighlightAnimation BREATH = new BalloonHighlightAnimation("BREATH", 3);
    public static final BalloonHighlightAnimation ROTATE = new BalloonHighlightAnimation("ROTATE", 4);

    private static final /* synthetic */ BalloonHighlightAnimation[] $values() {
        return new BalloonHighlightAnimation[]{NONE, HEARTBEAT, SHAKE, BREATH, ROTATE};
    }

    static {
        BalloonHighlightAnimation[] balloonHighlightAnimationArr$values = $values();
        $VALUES = balloonHighlightAnimationArr$values;
        $ENTRIES = AbstractC3328d.f(balloonHighlightAnimationArr$values);
    }

    private BalloonHighlightAnimation(String str, int i) {
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static BalloonHighlightAnimation valueOf(String str) {
        return (BalloonHighlightAnimation) Enum.valueOf(BalloonHighlightAnimation.class, str);
    }

    public static BalloonHighlightAnimation[] values() {
        return (BalloonHighlightAnimation[]) $VALUES.clone();
    }
}
