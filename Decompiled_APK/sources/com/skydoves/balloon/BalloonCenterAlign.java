package com.skydoves.balloon;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.skydoves.balloon.annotations.InternalBalloonApi;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes3.dex */
public final class BalloonCenterAlign {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ BalloonCenterAlign[] $VALUES;
    public static final BalloonCenterAlign START = new BalloonCenterAlign("START", 0);
    public static final BalloonCenterAlign END = new BalloonCenterAlign("END", 1);
    public static final BalloonCenterAlign TOP = new BalloonCenterAlign("TOP", 2);
    public static final BalloonCenterAlign BOTTOM = new BalloonCenterAlign("BOTTOM", 3);

    @Metadata
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

        static {
            int[] iArr = new int[BalloonCenterAlign.values().length];
            try {
                iArr[BalloonCenterAlign.START.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[BalloonCenterAlign.END.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[BalloonCenterAlign.TOP.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                iArr[BalloonCenterAlign.BOTTOM.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            $EnumSwitchMapping$0 = iArr;
        }
    }

    private static final /* synthetic */ BalloonCenterAlign[] $values() {
        return new BalloonCenterAlign[]{START, END, TOP, BOTTOM};
    }

    static {
        BalloonCenterAlign[] balloonCenterAlignArr$values = $values();
        $VALUES = balloonCenterAlignArr$values;
        $ENTRIES = AbstractC3328d.f(balloonCenterAlignArr$values);
    }

    private BalloonCenterAlign(String str, int i) {
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static BalloonCenterAlign valueOf(String str) {
        return (BalloonCenterAlign) Enum.valueOf(BalloonCenterAlign.class, str);
    }

    public static BalloonCenterAlign[] values() {
        return (BalloonCenterAlign[]) $VALUES.clone();
    }

    @InternalBalloonApi
    @NotNull
    public final BalloonAlign toAlign() {
        int i = WhenMappings.$EnumSwitchMapping$0[ordinal()];
        if (i == 1) {
            return BalloonAlign.START;
        }
        if (i == 2) {
            return BalloonAlign.END;
        }
        if (i == 3) {
            return BalloonAlign.TOP;
        }
        if (i == 4) {
            return BalloonAlign.BOTTOM;
        }
        throw new NoWhenBranchMatchedException();
    }
}
