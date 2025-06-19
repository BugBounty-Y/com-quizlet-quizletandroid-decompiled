package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class U0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ U0[] $VALUES;
    public static final U0 AUSTRALIA_HSC;
    public static final U0 AUSTRALIA_VCE;
    public static final U0 BRAZIL_ELL;
    public static final U0 BRAZIL_ENEM;

    @NotNull
    public static final T0 Companion;
    public static final U0 ENGLAND_A_LEVELS;
    public static final U0 ENGLAND_GCSE;
    public static final U0 FLASHCARDS_ELL;
    public static final U0 GERMANY_ABITUR;
    public static final U0 IELTS;
    public static final U0 INDIA_CSE;
    public static final U0 INDIA_JEE;
    public static final U0 INDIA_NEET;
    public static final U0 MEXICO_ELL;
    public static final U0 MEXICO_EXANI;
    public static final U0 POLAND_MATURA;
    public static final U0 SOLUTIONS_BRAZIL;
    public static final U0 SOLUTIONS_MEXICO;
    public static final U0 TOEFL;
    public static final U0 TOEIC;
    public static final U0 VIETNAM_ELL;

    @NotNull
    private final String value;

    static {
        U0 u0 = new U0("AUSTRALIA_HSC", 0, "/au/content/hsc");
        AUSTRALIA_HSC = u0;
        U0 u02 = new U0("AUSTRALIA_VCE", 1, "/au/content/vce");
        AUSTRALIA_VCE = u02;
        U0 u03 = new U0("BRAZIL_ELL", 2, "/br/content/ingles-vocabulario-nivel-iniciante");
        BRAZIL_ELL = u03;
        U0 u04 = new U0("BRAZIL_ENEM", 3, "/br/content/enem");
        BRAZIL_ENEM = u04;
        U0 u05 = new U0("ENGLAND_A_LEVELS", 4, "/gb/content/A-Levels");
        ENGLAND_A_LEVELS = u05;
        U0 u06 = new U0("ENGLAND_GCSE", 5, "/gb/content/gcse");
        ENGLAND_GCSE = u06;
        U0 u07 = new U0("FLASHCARDS_ELL", 6, "/subjects/languages/english-flashcards-62514826-t01");
        FLASHCARDS_ELL = u07;
        U0 u08 = new U0("GERMANY_ABITUR", 7, "/de/content/abiturvorbereitung");
        GERMANY_ABITUR = u08;
        U0 u09 = new U0("IELTS", 8, "/exams/ielts/ielts-vocabulary-f0c6693-s01");
        IELTS = u09;
        U0 u010 = new U0("INDIA_CSE", 9, "/in/content/upsc-cse-prelims");
        INDIA_CSE = u010;
        U0 u011 = new U0("INDIA_JEE", 10, "/in/content/jee-main");
        INDIA_JEE = u011;
        U0 u012 = new U0("INDIA_NEET", 11, "/in/content/neet-ug");
        INDIA_NEET = u012;
        U0 u013 = new U0("MEXICO_ELL", 12, "/mx/content/verbo-to-be");
        MEXICO_ELL = u013;
        U0 u014 = new U0("MEXICO_EXANI", 13, "/mx/content/exani");
        MEXICO_EXANI = u014;
        U0 u015 = new U0("POLAND_MATURA", 14, "/pl/content/matura");
        POLAND_MATURA = u015;
        U0 u016 = new U0("SOLUTIONS_BRAZIL", 15, "/br/explicacoes");
        SOLUTIONS_BRAZIL = u016;
        U0 u017 = new U0("SOLUTIONS_MEXICO", 16, "/mx/explicaciones");
        SOLUTIONS_MEXICO = u017;
        U0 u018 = new U0("TOEFL", 17, "/exams/toefl/toefl-vocabulary-e473ccd-s01");
        TOEFL = u018;
        U0 u019 = new U0("TOEIC", 18, "/exams/toeic/toeic-vocabulary-2af1fcc-s01");
        TOEIC = u019;
        U0 u020 = new U0("VIETNAM_ELL", 19, "/vn/content/tu-vung-tieng-anh-trinh-do-co-ban");
        VIETNAM_ELL = u020;
        U0[] u0Arr = {u0, u02, u03, u04, u05, u06, u07, u08, u09, u010, u011, u012, u013, u014, u015, u016, u017, u018, u019, u020};
        $VALUES = u0Arr;
        $ENTRIES = AbstractC3328d.f(u0Arr);
        Companion = new T0();
    }

    public U0(String str, int i, String str2) {
        this.value = str2;
    }

    public static U0 valueOf(String str) {
        return (U0) Enum.valueOf(U0.class, str);
    }

    public static U0[] values() {
        return (U0[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
