package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.s0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4518s0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4518s0[] $VALUES;
    public static final EnumC4518s0 CONSUMPTION_METER_REACHED;

    @NotNull
    public static final C4515r0 Companion;
    public static final EnumC4518s0 UPLOAD_METER_REACHED;

    @NotNull
    private final String value;

    static {
        EnumC4518s0 enumC4518s0 = new EnumC4518s0("CONSUMPTION_METER_REACHED", 0, "exception_practice_test_consumption_limit_reached");
        CONSUMPTION_METER_REACHED = enumC4518s0;
        EnumC4518s0 enumC4518s02 = new EnumC4518s0("UPLOAD_METER_REACHED", 1, "exception_practice_test_upload_limit_reached");
        UPLOAD_METER_REACHED = enumC4518s02;
        EnumC4518s0[] enumC4518s0Arr = {enumC4518s0, enumC4518s02};
        $VALUES = enumC4518s0Arr;
        $ENTRIES = AbstractC3328d.f(enumC4518s0Arr);
        Companion = new C4515r0();
    }

    public EnumC4518s0(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4518s0 valueOf(String str) {
        return (EnumC4518s0) Enum.valueOf(EnumC4518s0.class, str);
    }

    public static EnumC4518s0[] values() {
        return (EnumC4518s0[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
