package com.skydoves.balloon;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes3.dex */
public final class BalloonAlign {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ BalloonAlign[] $VALUES;
    public static final BalloonAlign START = new BalloonAlign("START", 0);
    public static final BalloonAlign END = new BalloonAlign("END", 1);
    public static final BalloonAlign TOP = new BalloonAlign("TOP", 2);
    public static final BalloonAlign BOTTOM = new BalloonAlign("BOTTOM", 3);

    private static final /* synthetic */ BalloonAlign[] $values() {
        return new BalloonAlign[]{START, END, TOP, BOTTOM};
    }

    static {
        BalloonAlign[] balloonAlignArr$values = $values();
        $VALUES = balloonAlignArr$values;
        $ENTRIES = AbstractC3328d.f(balloonAlignArr$values);
    }

    private BalloonAlign(String str, int i) {
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static BalloonAlign valueOf(String str) {
        return (BalloonAlign) Enum.valueOf(BalloonAlign.class, str);
    }

    public static BalloonAlign[] values() {
        return (BalloonAlign[]) $VALUES.clone();
    }
}
