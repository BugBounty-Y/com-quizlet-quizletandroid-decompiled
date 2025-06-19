package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class U1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ U1[] $VALUES;

    @NotNull
    public static final T1 Companion;
    public static final U1 MAIN;
    public static final U1 OTHER;
    private final int value;

    static {
        U1 u1 = new U1("OTHER", 0, 0);
        OTHER = u1;
        U1 u12 = new U1("MAIN", 1, 1);
        MAIN = u12;
        U1[] u1Arr = {u1, u12};
        $VALUES = u1Arr;
        $ENTRIES = AbstractC3328d.f(u1Arr);
        Companion = new T1();
    }

    public U1(String str, int i, int i2) {
        this.value = i2;
    }

    public static U1 valueOf(String str) {
        return (U1) Enum.valueOf(U1.class, str);
    }

    public static U1[] values() {
        return (U1[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
