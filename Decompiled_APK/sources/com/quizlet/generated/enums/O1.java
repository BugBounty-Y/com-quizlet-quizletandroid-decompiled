package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class O1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ O1[] $VALUES;
    public static final O1 CATEGORY;

    @NotNull
    public static final N1 Companion;
    public static final O1 DEFINITION;
    public static final O1 LOCATION;
    public static final O1 UNKNOWN;
    public static final O1 WORD;
    private final int value;

    static {
        O1 o1 = new O1("UNKNOWN", 0, 0);
        UNKNOWN = o1;
        O1 o12 = new O1("WORD", 1, 1);
        WORD = o12;
        O1 o13 = new O1("DEFINITION", 2, 2);
        DEFINITION = o13;
        O1 o14 = new O1("CATEGORY", 3, 3);
        CATEGORY = o14;
        O1 o15 = new O1("LOCATION", 4, 4);
        LOCATION = o15;
        O1[] o1Arr = {o1, o12, o13, o14, o15};
        $VALUES = o1Arr;
        $ENTRIES = AbstractC3328d.f(o1Arr);
        Companion = new N1();
    }

    public O1(String str, int i, int i2) {
        this.value = i2;
    }

    public static O1 valueOf(String str) {
        return (O1) Enum.valueOf(O1.class, str);
    }

    public static O1[] values() {
        return (O1[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
