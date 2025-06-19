package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class C1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ C1[] $VALUES;

    @NotNull
    public static final B1 Companion;
    public static final C1 SIMPLIFIED_SEQUENCING;
    public static final C1 STANDARD;
    public static final C1 START_ALL_AS_FAMILIAR;
    private final int value;

    static {
        C1 c1 = new C1("STANDARD", 0, 0);
        STANDARD = c1;
        C1 c12 = new C1("START_ALL_AS_FAMILIAR", 1, 1);
        START_ALL_AS_FAMILIAR = c12;
        C1 c13 = new C1("SIMPLIFIED_SEQUENCING", 2, 2);
        SIMPLIFIED_SEQUENCING = c13;
        C1[] c1Arr = {c1, c12, c13};
        $VALUES = c1Arr;
        $ENTRIES = AbstractC3328d.f(c1Arr);
        Companion = new B1();
    }

    public C1(String str, int i, int i2) {
        this.value = i2;
    }

    public static C1 valueOf(String str) {
        return (C1) Enum.valueOf(C1.class, str);
    }

    public static C1[] values() {
        return (C1[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
