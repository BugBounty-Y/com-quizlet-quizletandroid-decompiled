package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.e1, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4478e1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4478e1[] $VALUES;
    public static final EnumC4478e1 CLAZZ;
    public static final EnumC4478e1 COURSE;

    @NotNull
    public static final C4475d1 Companion;
    public static final EnumC4478e1 FOLDER;
    public static final EnumC4478e1 NOTE;
    public static final EnumC4478e1 PREP_PACK;
    public static final EnumC4478e1 QUESTION;
    public static final EnumC4478e1 QUESTION_BANK;
    public static final EnumC4478e1 QUIZLET_POWERED_FOLDER;
    public static final EnumC4478e1 SCHOOL;
    public static final EnumC4478e1 SET;
    public static final EnumC4478e1 TERM;
    public static final EnumC4478e1 TEXTBOOK;
    public static final EnumC4478e1 USER;
    public static final EnumC4478e1 VIDEO;

    @NotNull
    private final String value;

    static {
        EnumC4478e1 enumC4478e1 = new EnumC4478e1("CLAZZ", 0, "QClass");
        CLAZZ = enumC4478e1;
        EnumC4478e1 enumC4478e12 = new EnumC4478e1("COURSE", 1, "QCourse");
        COURSE = enumC4478e12;
        EnumC4478e1 enumC4478e13 = new EnumC4478e1("FOLDER", 2, "QFolder");
        FOLDER = enumC4478e13;
        EnumC4478e1 enumC4478e14 = new EnumC4478e1("NOTE", 3, "Note");
        NOTE = enumC4478e14;
        EnumC4478e1 enumC4478e15 = new EnumC4478e1("PREP_PACK", 4, "QPrepPack");
        PREP_PACK = enumC4478e15;
        EnumC4478e1 enumC4478e16 = new EnumC4478e1("QUESTION", 5, "ExplanationsQuestion");
        QUESTION = enumC4478e16;
        EnumC4478e1 enumC4478e17 = new EnumC4478e1("QUESTION_BANK", 6, "QuestionBank");
        QUESTION_BANK = enumC4478e17;
        EnumC4478e1 enumC4478e18 = new EnumC4478e1("QUIZLET_POWERED_FOLDER", 7, "QuizletPoweredFolder");
        QUIZLET_POWERED_FOLDER = enumC4478e18;
        EnumC4478e1 enumC4478e19 = new EnumC4478e1("SCHOOL", 8, "QSchool");
        SCHOOL = enumC4478e19;
        EnumC4478e1 enumC4478e110 = new EnumC4478e1("SET", 9, "QSet");
        SET = enumC4478e110;
        EnumC4478e1 enumC4478e111 = new EnumC4478e1("TERM", 10, "QTerm");
        TERM = enumC4478e111;
        EnumC4478e1 enumC4478e112 = new EnumC4478e1("TEXTBOOK", 11, "Textbook");
        TEXTBOOK = enumC4478e112;
        EnumC4478e1 enumC4478e113 = new EnumC4478e1("USER", 12, "QUser");
        USER = enumC4478e113;
        EnumC4478e1 enumC4478e114 = new EnumC4478e1("VIDEO", 13, "Video");
        VIDEO = enumC4478e114;
        EnumC4478e1[] enumC4478e1Arr = {enumC4478e1, enumC4478e12, enumC4478e13, enumC4478e14, enumC4478e15, enumC4478e16, enumC4478e17, enumC4478e18, enumC4478e19, enumC4478e110, enumC4478e111, enumC4478e112, enumC4478e113, enumC4478e114};
        $VALUES = enumC4478e1Arr;
        $ENTRIES = AbstractC3328d.f(enumC4478e1Arr);
        Companion = new C4475d1();
    }

    public EnumC4478e1(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4478e1 valueOf(String str) {
        return (EnumC4478e1) Enum.valueOf(EnumC4478e1.class, str);
    }

    public static EnumC4478e1[] values() {
        return (EnumC4478e1[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
