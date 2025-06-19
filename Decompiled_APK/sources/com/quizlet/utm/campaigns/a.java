package com.quizlet.utm.campaigns;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a implements com.quizlet.utm.b {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ a[] $VALUES;
    private final int index;
    public static final a SET_CREATION_SHARE = new a("SET_CREATION_SHARE", 0, 1);
    public static final a SET_PAGE_SHARE = new a("SET_PAGE_SHARE", 1, 2);
    public static final a MATCH_COMPLETE_SHARE = new a("MATCH_COMPLETE_SHARE", 2, 3);
    public static final a ADD_TO_CLASS_SHARE = new a("ADD_TO_CLASS_SHARE", 3, 4);
    public static final a FOLDER_PAGE_SHARE = new a("FOLDER_PAGE_SHARE", 4, 5);
    public static final a UK_TEACHER_REFERRAL = new a("UK_TEACHER_REFERRAL", 5, 6);
    public static final a LEARN_COMPLETE_SHARE = new a("LEARN_COMPLETE_SHARE", 6, 7);
    public static final a FLASHCARD_COMPLETE_SHARE = new a("FLASHCARD_COMPLETE_SHARE", 7, 8);
    public static final a TEST_COMPLETE_SHARE = new a("TEST_COMPLETE_SHARE", 8, 9);
    public static final a MATCH_COMPLETE_SHARE_WITHOUT_SCORE = new a("MATCH_COMPLETE_SHARE_WITHOUT_SCORE", 9, 10);
    public static final a LIVE_TEACHER_SHARE = new a("LIVE_TEACHER_SHARE", 10, 11);
    public static final a SET_ADDED_TO_CLASS = new a("SET_ADDED_TO_CLASS", 11, 12);
    public static final a STUDENT_REFERRAL = new a("STUDENT_REFERRAL", 12, 13);
    public static final a TEACHER_REFERRAL = new a("TEACHER_REFERRAL", 13, 14);
    public static final a PREP_PACK_PAGE_SHARE = new a("PREP_PACK_PAGE_SHARE", 14, 15);
    public static final a CLASS_MEMBERS_POPUP_SHARE = new a("CLASS_MEMBERS_POPUP_SHARE", 15, 16);
    public static final a CLASS_MEMBERS_TAB_SHARE = new a("CLASS_MEMBERS_TAB_SHARE", 16, 17);
    public static final a EXPLANATIONS_TEXTBOOK_SHARE = new a("EXPLANATIONS_TEXTBOOK_SHARE", 17, 18);
    public static final a EXPLANATIONS_TEXTBOOK_EXERCISE_SHARE = new a("EXPLANATIONS_TEXTBOOK_EXERCISE_SHARE", 18, 19);
    public static final a EXPLANATIONS_QUESTION_SHARE = new a("EXPLANATIONS_QUESTION_SHARE", 19, 20);
    public static final a COURSE_INSTANCE_SHARE = new a("COURSE_INSTANCE_SHARE", 20, 21);

    private static final /* synthetic */ a[] $values() {
        return new a[]{SET_CREATION_SHARE, SET_PAGE_SHARE, MATCH_COMPLETE_SHARE, ADD_TO_CLASS_SHARE, FOLDER_PAGE_SHARE, UK_TEACHER_REFERRAL, LEARN_COMPLETE_SHARE, FLASHCARD_COMPLETE_SHARE, TEST_COMPLETE_SHARE, MATCH_COMPLETE_SHARE_WITHOUT_SCORE, LIVE_TEACHER_SHARE, SET_ADDED_TO_CLASS, STUDENT_REFERRAL, TEACHER_REFERRAL, PREP_PACK_PAGE_SHARE, CLASS_MEMBERS_POPUP_SHARE, CLASS_MEMBERS_TAB_SHARE, EXPLANATIONS_TEXTBOOK_SHARE, EXPLANATIONS_TEXTBOOK_EXERCISE_SHARE, EXPLANATIONS_QUESTION_SHARE, COURSE_INSTANCE_SHARE};
    }

    static {
        a[] aVarArr$values = $values();
        $VALUES = aVarArr$values;
        $ENTRIES = AbstractC3328d.f(aVarArr$values);
    }

    private a(String str, int i, int i2) {
        this.index = i2;
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) $VALUES.clone();
    }

    @Override // com.quizlet.utm.b
    public int getIndex() {
        return this.index;
    }
}
