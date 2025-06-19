package com.skydoves.balloon.animations;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes3.dex */
public final class BalloonRotateDirection {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ BalloonRotateDirection[] $VALUES;
    private final int value;
    public static final BalloonRotateDirection RIGHT = new BalloonRotateDirection("RIGHT", 0, 1);
    public static final BalloonRotateDirection LEFT = new BalloonRotateDirection("LEFT", 1, -1);

    private static final /* synthetic */ BalloonRotateDirection[] $values() {
        return new BalloonRotateDirection[]{RIGHT, LEFT};
    }

    static {
        BalloonRotateDirection[] balloonRotateDirectionArr$values = $values();
        $VALUES = balloonRotateDirectionArr$values;
        $ENTRIES = AbstractC3328d.f(balloonRotateDirectionArr$values);
    }

    private BalloonRotateDirection(String str, int i, int i2) {
        this.value = i2;
    }

    @NotNull
    public static a getEntries() {
        return $ENTRIES;
    }

    public static BalloonRotateDirection valueOf(String str) {
        return (BalloonRotateDirection) Enum.valueOf(BalloonRotateDirection.class, str);
    }

    public static BalloonRotateDirection[] values() {
        return (BalloonRotateDirection[]) $VALUES.clone();
    }

    public final int getValue() {
        return this.value;
    }
}
