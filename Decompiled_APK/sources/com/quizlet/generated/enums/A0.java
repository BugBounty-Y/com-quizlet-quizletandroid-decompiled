package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class A0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ A0[] $VALUES;

    @NotNull
    public static final C4535z0 Companion;
    public static final A0 REFERENCE_CONTENT;

    @NotNull
    private final String value = "reference_content";

    static {
        A0 a0 = new A0();
        REFERENCE_CONTENT = a0;
        A0[] a0Arr = {a0};
        $VALUES = a0Arr;
        $ENTRIES = AbstractC3328d.f(a0Arr);
        Companion = new C4535z0();
    }

    public static A0 valueOf(String str) {
        return (A0) Enum.valueOf(A0.class, str);
    }

    public static A0[] values() {
        return (A0[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
