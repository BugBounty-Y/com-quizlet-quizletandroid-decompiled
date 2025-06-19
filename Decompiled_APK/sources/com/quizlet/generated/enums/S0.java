package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class S0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ S0[] $VALUES;
    public static final S0 AUSTRALIA_HSC;
    public static final S0 AUSTRALIA_VCE;
    public static final S0 BRAZIL_ELL;
    public static final S0 BRAZIL_ENEM;

    @NotNull
    public static final R0 Companion;
    public static final S0 ENGLAND_A_LEVELS;
    public static final S0 ENGLAND_GCSE;
    public static final S0 FLASHCARDS_ELL;
    public static final S0 GERMANY_ABITUR;
    public static final S0 IELTS;
    public static final S0 INDIA_CSE;
    public static final S0 INDIA_JEE;
    public static final S0 INDIA_NEET;
    public static final S0 MEXICO_ELL;
    public static final S0 MEXICO_EXANI;
    public static final S0 POLAND_MATURA;
    public static final S0 SOLUTIONS_BRAZIL;
    public static final S0 SOLUTIONS_MEXICO;
    public static final S0 TOEFL;
    public static final S0 TOEIC;
    public static final S0 VIETNAM_ELL;

    @NotNull
    private final String value;

    static {
        S0 s0 = new S0("AUSTRALIA_HSC", 0, "australia_hsc");
        AUSTRALIA_HSC = s0;
        S0 s02 = new S0("AUSTRALIA_VCE", 1, "australia_vce");
        AUSTRALIA_VCE = s02;
        S0 s03 = new S0("BRAZIL_ELL", 2, "brazil_ell");
        BRAZIL_ELL = s03;
        S0 s04 = new S0("BRAZIL_ENEM", 3, "brazil_enem");
        BRAZIL_ENEM = s04;
        S0 s05 = new S0("ENGLAND_A_LEVELS", 4, "england_alevels");
        ENGLAND_A_LEVELS = s05;
        S0 s06 = new S0("ENGLAND_GCSE", 5, "england_gcse");
        ENGLAND_GCSE = s06;
        S0 s07 = new S0("FLASHCARDS_ELL", 6, "flashcards_ell");
        FLASHCARDS_ELL = s07;
        S0 s08 = new S0("GERMANY_ABITUR", 7, "germany_abitur");
        GERMANY_ABITUR = s08;
        S0 s09 = new S0("IELTS", 8, "ielts");
        IELTS = s09;
        S0 s010 = new S0("INDIA_CSE", 9, "india_cse");
        INDIA_CSE = s010;
        S0 s011 = new S0("INDIA_JEE", 10, "india_jee");
        INDIA_JEE = s011;
        S0 s012 = new S0("INDIA_NEET", 11, "india_neet");
        INDIA_NEET = s012;
        S0 s013 = new S0("MEXICO_ELL", 12, "mexico_ell");
        MEXICO_ELL = s013;
        S0 s014 = new S0("MEXICO_EXANI", 13, "mexico_exani");
        MEXICO_EXANI = s014;
        S0 s015 = new S0("POLAND_MATURA", 14, "poland_matura");
        POLAND_MATURA = s015;
        S0 s016 = new S0("SOLUTIONS_BRAZIL", 15, "solutions_brazil");
        SOLUTIONS_BRAZIL = s016;
        S0 s017 = new S0("SOLUTIONS_MEXICO", 16, "solutions_mexico");
        SOLUTIONS_MEXICO = s017;
        S0 s018 = new S0("TOEFL", 17, "toefl");
        TOEFL = s018;
        S0 s019 = new S0("TOEIC", 18, "toeic");
        TOEIC = s019;
        S0 s020 = new S0("VIETNAM_ELL", 19, "vietnam_ell");
        VIETNAM_ELL = s020;
        S0[] s0Arr = {s0, s02, s03, s04, s05, s06, s07, s08, s09, s010, s011, s012, s013, s014, s015, s016, s017, s018, s019, s020};
        $VALUES = s0Arr;
        $ENTRIES = AbstractC3328d.f(s0Arr);
        Companion = new R0();
    }

    public S0(String str, int i, String str2) {
        this.value = str2;
    }

    public static S0 valueOf(String str) {
        return (S0) Enum.valueOf(S0.class, str);
    }

    public static S0[] values() {
        return (S0[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
