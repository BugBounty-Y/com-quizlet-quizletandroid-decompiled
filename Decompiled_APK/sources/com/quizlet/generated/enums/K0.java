package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class K0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ K0[] $VALUES;
    public static final K0 BUNDLED;

    @NotNull
    public static final J0 Companion;
    public static final K0 FREE;
    public static final K0 PAID;
    public static final K0 UNLAUNCHED;
    private final int value;

    static {
        K0 k0 = new K0("FREE", 0, 0);
        FREE = k0;
        K0 k02 = new K0("PAID", 1, 1);
        PAID = k02;
        K0 k03 = new K0("UNLAUNCHED", 2, 2);
        UNLAUNCHED = k03;
        K0 k04 = new K0("BUNDLED", 3, 3);
        BUNDLED = k04;
        K0[] k0Arr = {k0, k02, k03, k04};
        $VALUES = k0Arr;
        $ENTRIES = AbstractC3328d.f(k0Arr);
        Companion = new J0();
    }

    public K0(String str, int i, int i2) {
        this.value = i2;
    }

    public static K0 valueOf(String str) {
        return (K0) Enum.valueOf(K0.class, str);
    }

    public static K0[] values() {
        return (K0[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
