package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.u0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4524u0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4524u0[] $VALUES;

    @NotNull
    public static final C4521t0 Companion;
    public static final EnumC4524u0 INITIAL_WAIT_MS;
    public static final EnumC4524u0 INTERVAL_MS;
    public static final EnumC4524u0 MAX_SERVER_ERROR_RETRIES;
    public static final EnumC4524u0 TOTAL_TIMEOUT_MS;
    private final int value;

    static {
        EnumC4524u0 enumC4524u0 = new EnumC4524u0("INITIAL_WAIT_MS", 0, 0);
        INITIAL_WAIT_MS = enumC4524u0;
        EnumC4524u0 enumC4524u02 = new EnumC4524u0("INTERVAL_MS", 1, 1);
        INTERVAL_MS = enumC4524u02;
        EnumC4524u0 enumC4524u03 = new EnumC4524u0("MAX_SERVER_ERROR_RETRIES", 2, 2);
        MAX_SERVER_ERROR_RETRIES = enumC4524u03;
        EnumC4524u0 enumC4524u04 = new EnumC4524u0("TOTAL_TIMEOUT_MS", 3, 3);
        TOTAL_TIMEOUT_MS = enumC4524u04;
        EnumC4524u0[] enumC4524u0Arr = {enumC4524u0, enumC4524u02, enumC4524u03, enumC4524u04};
        $VALUES = enumC4524u0Arr;
        $ENTRIES = AbstractC3328d.f(enumC4524u0Arr);
        Companion = new C4521t0();
    }

    public EnumC4524u0(String str, int i, int i2) {
        this.value = i2;
    }

    public static EnumC4524u0 valueOf(String str) {
        return (EnumC4524u0) Enum.valueOf(EnumC4524u0.class, str);
    }

    public static EnumC4524u0[] values() {
        return (EnumC4524u0[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
