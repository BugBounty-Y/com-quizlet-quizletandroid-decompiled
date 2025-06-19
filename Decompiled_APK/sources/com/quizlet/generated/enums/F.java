package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class F {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ F[] $VALUES;
    public static final F BAD_QUALITY;

    @NotNull
    public static final E Companion;
    public static final F OTHER;
    public static final F WRONG_CONTENT;
    public static final F WRONG_TIMING;

    @NotNull
    private final String value;

    static {
        F f = new F("BAD_QUALITY", 0, "bad_quality");
        BAD_QUALITY = f;
        F f2 = new F("OTHER", 1, "other");
        OTHER = f2;
        F f3 = new F("WRONG_CONTENT", 2, "wrong_content");
        WRONG_CONTENT = f3;
        F f4 = new F("WRONG_TIMING", 3, "wrong_timing");
        WRONG_TIMING = f4;
        F[] fArr = {f, f2, f3, f4};
        $VALUES = fArr;
        $ENTRIES = AbstractC3328d.f(fArr);
        Companion = new E();
    }

    public F(String str, int i, String str2) {
        this.value = str2;
    }

    public static F valueOf(String str) {
        return (F) Enum.valueOf(F.class, str);
    }

    public static F[] values() {
        return (F[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
