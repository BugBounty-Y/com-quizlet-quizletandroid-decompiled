package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class W0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ W0[] $VALUES;

    @NotNull
    public static final V0 Companion;
    public static final W0 LITERATURE_GUIDE;
    public static final W0 STANDARDIZED_EXAM;
    public static final W0 SUBJECT;

    @NotNull
    private final String value;

    static {
        W0 w0 = new W0("LITERATURE_GUIDE", 0, "literature_guide");
        LITERATURE_GUIDE = w0;
        W0 w02 = new W0("STANDARDIZED_EXAM", 1, "standardized_exam");
        STANDARDIZED_EXAM = w02;
        W0 w03 = new W0("SUBJECT", 2, "subject");
        SUBJECT = w03;
        W0[] w0Arr = {w0, w02, w03};
        $VALUES = w0Arr;
        $ENTRIES = AbstractC3328d.f(w0Arr);
        Companion = new V0();
    }

    public W0(String str, int i, String str2) {
        this.value = str2;
    }

    public static W0 valueOf(String str) {
        return (W0) Enum.valueOf(W0.class, str);
    }

    public static W0[] values() {
        return (W0[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
