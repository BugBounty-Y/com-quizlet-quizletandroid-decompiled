package com.quizlet.utm.campaigns;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.utm.c;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class b implements c {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ b[] $VALUES;

    @NotNull
    public static final a Companion;

    @NotNull
    private final String value;
    public static final b SET_CREATION_SHARE = new b("SET_CREATION_SHARE", 0, "set-creation-share");
    public static final b SET_PAGE_SHARE = new b("SET_PAGE_SHARE", 1, "set-page-share");
    public static final b MATCH_COMPLETE_SHARE = new b("MATCH_COMPLETE_SHARE", 2, "match-complete-share");
    public static final b ADD_TO_CLASS_SHARE = new b("ADD_TO_CLASS_SHARE", 3, "add-to-class-share");
    public static final b FOLDER_PAGE_SHARE = new b("FOLDER_PAGE_SHARE", 4, "folder-page-share");
    public static final b UK_TEACHER_REFERRAL = new b("UK_TEACHER_REFERRAL", 5, "uk-teacher-referral");
    public static final b LEARN_COMPLETE_SHARE = new b("LEARN_COMPLETE_SHARE", 6, "learn-complete-share");
    public static final b FLASHCARD_COMPLETE_SHARE = new b("FLASHCARD_COMPLETE_SHARE", 7, "flashcard-complete-share");
    public static final b TEST_COMPLETE_SHARE = new b("TEST_COMPLETE_SHARE", 8, "test-complete-share");
    public static final b MATCH_COMPLETE_SHARE_WITHOUT_SCORE = new b("MATCH_COMPLETE_SHARE_WITHOUT_SCORE", 9, "match-complete-share-without-score");
    public static final b LIVE_TEACHER_SHARE = new b("LIVE_TEACHER_SHARE", 10, "live-teacher-share");
    public static final b SET_ADDED_TO_CLASS = new b("SET_ADDED_TO_CLASS", 11, "set-added-to-class");
    public static final b STUDENT_REFERRAL = new b("STUDENT_REFERRAL", 12, "student-referral");
    public static final b TEACHER_REFERRAL = new b("TEACHER_REFERRAL", 13, "teacher-referral");
    public static final b PREP_PACK_PAGE_SHARE = new b("PREP_PACK_PAGE_SHARE", 14, "prep-pack-page-share");
    public static final b CLASS_MEMBERS_POPUP_SHARE = new b("CLASS_MEMBERS_POPUP_SHARE", 15, "class-members-popup-share");
    public static final b CLASS_MEMBERS_TAB_SHARE = new b("CLASS_MEMBERS_TAB_SHARE", 16, "class-members-tab-share");
    public static final b EXPLANATIONS_TEXTBOOK_SHARE = new b("EXPLANATIONS_TEXTBOOK_SHARE", 17, "explanations-textbook-share");
    public static final b EXPLANATIONS_TEXTBOOK_EXERCISE_SHARE = new b("EXPLANATIONS_TEXTBOOK_EXERCISE_SHARE", 18, "explanations-textbook-exercise-share");
    public static final b EXPLANATIONS_QUESTION_SHARE = new b("EXPLANATIONS_QUESTION_SHARE", 19, "explanations-question-share");
    public static final b COURSE_INSTANCE_SHARE = new b("COURSE_INSTANCE_SHARE", 20, "course-instance-share");

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final b fromValue(String str) {
            for (b bVar : b.values()) {
                if (Intrinsics.b(bVar.getValue(), str)) {
                    return bVar;
                }
            }
            return null;
        }

        private a() {
        }
    }

    private static final /* synthetic */ b[] $values() {
        return new b[]{SET_CREATION_SHARE, SET_PAGE_SHARE, MATCH_COMPLETE_SHARE, ADD_TO_CLASS_SHARE, FOLDER_PAGE_SHARE, UK_TEACHER_REFERRAL, LEARN_COMPLETE_SHARE, FLASHCARD_COMPLETE_SHARE, TEST_COMPLETE_SHARE, MATCH_COMPLETE_SHARE_WITHOUT_SCORE, LIVE_TEACHER_SHARE, SET_ADDED_TO_CLASS, STUDENT_REFERRAL, TEACHER_REFERRAL, PREP_PACK_PAGE_SHARE, CLASS_MEMBERS_POPUP_SHARE, CLASS_MEMBERS_TAB_SHARE, EXPLANATIONS_TEXTBOOK_SHARE, EXPLANATIONS_TEXTBOOK_EXERCISE_SHARE, EXPLANATIONS_QUESTION_SHARE, COURSE_INSTANCE_SHARE};
    }

    static {
        b[] bVarArr$values = $values();
        $VALUES = bVarArr$values;
        $ENTRIES = AbstractC3328d.f(bVarArr$values);
        Companion = new a(null);
    }

    private b(String str, int i, String str2) {
        this.value = str2;
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) $VALUES.clone();
    }

    @Override // com.quizlet.utm.c
    @NotNull
    public String getValue() {
        return this.value;
    }
}
