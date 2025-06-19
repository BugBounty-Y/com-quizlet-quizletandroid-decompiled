package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class Q1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ Q1[] $VALUES;

    @NotNull
    public static final P1 Companion;
    public static final Q1 GRADE_TEXT;
    public static final Q1 REQUEST_END;
    public static final Q1 REQUEST_START;

    @NotNull
    private final String value;

    static {
        Q1 q1 = new Q1("REQUEST_START", 0, "request_start");
        REQUEST_START = q1;
        Q1 q12 = new Q1("REQUEST_END", 1, "request_end");
        REQUEST_END = q12;
        Q1 q13 = new Q1("GRADE_TEXT", 2, "grade_text");
        GRADE_TEXT = q13;
        Q1[] q1Arr = {q1, q12, q13};
        $VALUES = q1Arr;
        $ENTRIES = AbstractC3328d.f(q1Arr);
        Companion = new P1();
    }

    public Q1(String str, int i, String str2) {
        this.value = str2;
    }

    public static Q1 valueOf(String str) {
        return (Q1) Enum.valueOf(Q1.class, str);
    }

    public static Q1[] values() {
        return (Q1[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
