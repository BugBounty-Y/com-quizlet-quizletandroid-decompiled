package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.db.data.models.base.AssociationNames;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class M1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ M1[] $VALUES;
    public static final M1 CLASS_PLACEMENT;
    public static final M1 CREATE_SET_PAGE;

    @NotNull
    public static final L1 Companion;
    public static final M1 HOME_PLACEMENT;
    public static final M1 LEARN_MODE_PAGE;
    public static final M1 MISC;
    public static final M1 QUESTION_DETAIL;
    public static final M1 SETTINGS_PAGE;
    public static final M1 SET_PAGE;
    public static final M1 SIGNUP_PAGE;
    public static final M1 TEXTBOOK;
    public static final M1 TEXTBOOK_EXERCISE;
    public static final M1 WRITE_MODE_PAGE;

    @NotNull
    private final String value;

    static {
        M1 m1 = new M1("CLASS_PLACEMENT", 0, AssociationNames.CLASS);
        CLASS_PLACEMENT = m1;
        M1 m12 = new M1("CREATE_SET_PAGE", 1, "create_set_page");
        CREATE_SET_PAGE = m12;
        M1 m13 = new M1("HOME_PLACEMENT", 2, "home");
        HOME_PLACEMENT = m13;
        M1 m14 = new M1("LEARN_MODE_PAGE", 3, "learn_mode_page");
        LEARN_MODE_PAGE = m14;
        M1 m15 = new M1("MISC", 4, "misc");
        MISC = m15;
        M1 m16 = new M1("QUESTION_DETAIL", 5, "question_detail");
        QUESTION_DETAIL = m16;
        M1 m17 = new M1("SET_PAGE", 6, "set_page");
        SET_PAGE = m17;
        M1 m18 = new M1("SETTINGS_PAGE", 7, "settings_page");
        SETTINGS_PAGE = m18;
        M1 m19 = new M1("SIGNUP_PAGE", 8, "signup_page");
        SIGNUP_PAGE = m19;
        M1 m110 = new M1("TEXTBOOK", 9, "textbook");
        TEXTBOOK = m110;
        M1 m111 = new M1("TEXTBOOK_EXERCISE", 10, "textbook_exercise");
        TEXTBOOK_EXERCISE = m111;
        M1 m112 = new M1("WRITE_MODE_PAGE", 11, "write_mode_page");
        WRITE_MODE_PAGE = m112;
        M1[] m1Arr = {m1, m12, m13, m14, m15, m16, m17, m18, m19, m110, m111, m112};
        $VALUES = m1Arr;
        $ENTRIES = AbstractC3328d.f(m1Arr);
        Companion = new L1();
    }

    public M1(String str, int i, String str2) {
        this.value = str2;
    }

    public static M1 valueOf(String str) {
        return (M1) Enum.valueOf(M1.class, str);
    }

    public static M1[] values() {
        return (M1[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
