package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class I1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ I1[] $VALUES;
    public static final I1 ARTS_AND_HUMANITIES;

    @NotNull
    public static final H1 Companion;
    public static final I1 LANGUAGES;
    public static final I1 MATH;
    public static final I1 SCIENCE;
    public static final I1 SOCIAL_SCIENCE;

    @NotNull
    private final String value;

    static {
        I1 i1 = new I1("ARTS_AND_HUMANITIES", 0, "arts_and_humanities");
        ARTS_AND_HUMANITIES = i1;
        I1 i12 = new I1("LANGUAGES", 1, "languages");
        LANGUAGES = i12;
        I1 i13 = new I1("MATH", 2, "math");
        MATH = i13;
        I1 i14 = new I1("SCIENCE", 3, "science");
        SCIENCE = i14;
        I1 i15 = new I1("SOCIAL_SCIENCE", 4, "social_science");
        SOCIAL_SCIENCE = i15;
        I1[] i1Arr = {i1, i12, i13, i14, i15};
        $VALUES = i1Arr;
        $ENTRIES = AbstractC3328d.f(i1Arr);
        Companion = new H1();
    }

    public I1(String str, int i, String str2) {
        this.value = str2;
    }

    public static I1 valueOf(String str) {
        return (I1) Enum.valueOf(I1.class, str);
    }

    public static I1[] values() {
        return (I1[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
