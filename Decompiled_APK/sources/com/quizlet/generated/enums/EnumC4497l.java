package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.l, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4497l {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4497l[] $VALUES;

    @NotNull
    public static final C4494k Companion;
    public static final EnumC4497l LANGUAGES;
    public static final EnumC4497l LITERATURE;
    public static final EnumC4497l MATH;
    public static final EnumC4497l SCIENCE;
    public static final EnumC4497l SOCIAL_SCIENCE;
    public static final EnumC4497l STANDARDIZED_ENGLISH;
    public static final EnumC4497l STANDARDIZED_TEST;

    @NotNull
    private final String value;

    static {
        EnumC4497l enumC4497l = new EnumC4497l("MATH", 0, "math");
        MATH = enumC4497l;
        EnumC4497l enumC4497l2 = new EnumC4497l("SCIENCE", 1, "science");
        SCIENCE = enumC4497l2;
        EnumC4497l enumC4497l3 = new EnumC4497l("LANGUAGES", 2, "languages");
        LANGUAGES = enumC4497l3;
        EnumC4497l enumC4497l4 = new EnumC4497l("LITERATURE", 3, "literature");
        LITERATURE = enumC4497l4;
        EnumC4497l enumC4497l5 = new EnumC4497l("SOCIAL_SCIENCE", 4, "social-science");
        SOCIAL_SCIENCE = enumC4497l5;
        EnumC4497l enumC4497l6 = new EnumC4497l("STANDARDIZED_ENGLISH", 5, "standardized-english");
        STANDARDIZED_ENGLISH = enumC4497l6;
        EnumC4497l enumC4497l7 = new EnumC4497l("STANDARDIZED_TEST", 6, "standardized-test");
        STANDARDIZED_TEST = enumC4497l7;
        EnumC4497l[] enumC4497lArr = {enumC4497l, enumC4497l2, enumC4497l3, enumC4497l4, enumC4497l5, enumC4497l6, enumC4497l7};
        $VALUES = enumC4497lArr;
        $ENTRIES = AbstractC3328d.f(enumC4497lArr);
        Companion = new C4494k();
    }

    public EnumC4497l(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4497l valueOf(String str) {
        return (EnumC4497l) Enum.valueOf(EnumC4497l.class, str);
    }

    public static EnumC4497l[] values() {
        return (EnumC4497l[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
