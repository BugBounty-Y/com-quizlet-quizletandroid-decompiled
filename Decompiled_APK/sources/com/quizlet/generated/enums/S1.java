package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class S1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ S1[] $VALUES;
    public static final S1 ADD_SET_TO_CLASS;

    @NotNull
    public static final R1 Companion;
    public static final S1 NEW_USER_NOTIFICATION;
    public static final S1 RECOMMENDED_SET;
    public static final S1 REENGAGEMENT_NOTIFICATION;
    public static final S1 SRS_NOTIFICATION;
    public static final S1 STUDY_DUE_FOLDER;
    public static final S1 STUDY_DUE_USER_STUDYABLE;
    public static final S1 STUDY_NEXT_DAY_REMINDER;
    public static final S1 SWIPE_NOTIFICATION;
    private final int value;

    static {
        S1 s1 = new S1("STUDY_DUE_FOLDER", 0, 1);
        STUDY_DUE_FOLDER = s1;
        S1 s12 = new S1("STUDY_DUE_USER_STUDYABLE", 1, 2);
        STUDY_DUE_USER_STUDYABLE = s12;
        S1 s13 = new S1("STUDY_NEXT_DAY_REMINDER", 2, 3);
        STUDY_NEXT_DAY_REMINDER = s13;
        S1 s14 = new S1("NEW_USER_NOTIFICATION", 3, 4);
        NEW_USER_NOTIFICATION = s14;
        S1 s15 = new S1("REENGAGEMENT_NOTIFICATION", 4, 5);
        REENGAGEMENT_NOTIFICATION = s15;
        S1 s16 = new S1("SWIPE_NOTIFICATION", 5, 6);
        SWIPE_NOTIFICATION = s16;
        S1 s17 = new S1("RECOMMENDED_SET", 6, 7);
        RECOMMENDED_SET = s17;
        S1 s18 = new S1("ADD_SET_TO_CLASS", 7, 8);
        ADD_SET_TO_CLASS = s18;
        S1 s19 = new S1("SRS_NOTIFICATION", 8, 9);
        SRS_NOTIFICATION = s19;
        S1[] s1Arr = {s1, s12, s13, s14, s15, s16, s17, s18, s19};
        $VALUES = s1Arr;
        $ENTRIES = AbstractC3328d.f(s1Arr);
        Companion = new R1();
    }

    public S1(String str, int i, int i2) {
        this.value = i2;
    }

    public static S1 valueOf(String str) {
        return (S1) Enum.valueOf(S1.class, str);
    }

    public static S1[] values() {
        return (S1[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
