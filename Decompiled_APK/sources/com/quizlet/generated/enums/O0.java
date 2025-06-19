package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class O0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ O0[] $VALUES;
    public static final O0 ANSWER;

    @NotNull
    public static final N0 Companion;
    public static final O0 PROMPT;
    private final int value;

    static {
        O0 o0 = new O0("PROMPT", 0, 1);
        PROMPT = o0;
        O0 o02 = new O0("ANSWER", 1, 2);
        ANSWER = o02;
        O0[] o0Arr = {o0, o02};
        $VALUES = o0Arr;
        $ENTRIES = AbstractC3328d.f(o0Arr);
        Companion = new N0();
    }

    public O0(String str, int i, int i2) {
        this.value = i2;
    }

    public static O0 valueOf(String str) {
        return (O0) Enum.valueOf(O0.class, str);
    }

    public static O0[] values() {
        return (O0[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
