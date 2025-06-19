package com.skydoves.balloon;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes3.dex */
public final class ArrowOrientation {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ ArrowOrientation[] $VALUES;

    @NotNull
    public static final Companion Companion;
    public static final ArrowOrientation BOTTOM = new ArrowOrientation("BOTTOM", 0);
    public static final ArrowOrientation TOP = new ArrowOrientation("TOP", 1);
    public static final ArrowOrientation START = new ArrowOrientation("START", 2);
    public static final ArrowOrientation END = new ArrowOrientation("END", 3);

    @Metadata
    public static final class Companion {

        @Metadata
        public /* synthetic */ class WhenMappings {
            public static final /* synthetic */ int[] $EnumSwitchMapping$0;

            static {
                int[] iArr = new int[ArrowOrientation.values().length];
                try {
                    iArr[ArrowOrientation.START.ordinal()] = 1;
                } catch (NoSuchFieldError unused) {
                }
                try {
                    iArr[ArrowOrientation.END.ordinal()] = 2;
                } catch (NoSuchFieldError unused2) {
                }
                $EnumSwitchMapping$0 = iArr;
            }
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final ArrowOrientation getRTLSupportOrientation$balloon_release(@NotNull ArrowOrientation arrowOrientation, boolean z) {
            Intrinsics.checkNotNullParameter(arrowOrientation, "<this>");
            if (z) {
                int i = WhenMappings.$EnumSwitchMapping$0[arrowOrientation.ordinal()];
                if (i == 1) {
                    return ArrowOrientation.END;
                }
                if (i == 2) {
                    return ArrowOrientation.START;
                }
            }
            return arrowOrientation;
        }

        private Companion() {
        }
    }

    private static final /* synthetic */ ArrowOrientation[] $values() {
        return new ArrowOrientation[]{BOTTOM, TOP, START, END};
    }

    static {
        ArrowOrientation[] arrowOrientationArr$values = $values();
        $VALUES = arrowOrientationArr$values;
        $ENTRIES = AbstractC3328d.f(arrowOrientationArr$values);
        Companion = new Companion(null);
    }

    private ArrowOrientation(String str, int i) {
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static ArrowOrientation valueOf(String str) {
        return (ArrowOrientation) Enum.valueOf(ArrowOrientation.class, str);
    }

    public static ArrowOrientation[] values() {
        return (ArrowOrientation[]) $VALUES.clone();
    }
}
