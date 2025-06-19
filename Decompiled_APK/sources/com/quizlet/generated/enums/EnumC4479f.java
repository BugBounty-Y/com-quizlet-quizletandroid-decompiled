package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4479f {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4479f[] $VALUES;

    @NotNull
    public static final C4476e Companion;
    public static final EnumC4479f DAILY_STREAKS;
    public static final EnumC4479f DAY;
    public static final EnumC4479f EXPLANATIONS_STUDIED;
    public static final EnumC4479f NONE;
    public static final EnumC4479f ROUNDS_STUDIED;
    public static final EnumC4479f SETS_STUDIED;
    public static final EnumC4479f STUDY_GUIDES_CREATED;
    public static final EnumC4479f WEEK;
    public static final EnumC4479f WEEKLY_STREAKS;

    @NotNull
    private final String value;

    static {
        EnumC4479f enumC4479f = new EnumC4479f("DAY", 0, "Day");
        DAY = enumC4479f;
        EnumC4479f enumC4479f2 = new EnumC4479f("WEEK", 1, "Week");
        WEEK = enumC4479f2;
        EnumC4479f enumC4479f3 = new EnumC4479f("DAILY_STREAKS", 2, "DailyStreaks");
        DAILY_STREAKS = enumC4479f3;
        EnumC4479f enumC4479f4 = new EnumC4479f("WEEKLY_STREAKS", 3, "WeeklyStreaks");
        WEEKLY_STREAKS = enumC4479f4;
        EnumC4479f enumC4479f5 = new EnumC4479f("SETS_STUDIED", 4, "SetsStudied");
        SETS_STUDIED = enumC4479f5;
        EnumC4479f enumC4479f6 = new EnumC4479f("ROUNDS_STUDIED", 5, "RoundsStudied");
        ROUNDS_STUDIED = enumC4479f6;
        EnumC4479f enumC4479f7 = new EnumC4479f("EXPLANATIONS_STUDIED", 6, "ExplanationsStudied");
        EXPLANATIONS_STUDIED = enumC4479f7;
        EnumC4479f enumC4479f8 = new EnumC4479f("STUDY_GUIDES_CREATED", 7, "StudyGuidesCreated");
        STUDY_GUIDES_CREATED = enumC4479f8;
        EnumC4479f enumC4479f9 = new EnumC4479f("NONE", 8, "None");
        NONE = enumC4479f9;
        EnumC4479f[] enumC4479fArr = {enumC4479f, enumC4479f2, enumC4479f3, enumC4479f4, enumC4479f5, enumC4479f6, enumC4479f7, enumC4479f8, enumC4479f9};
        $VALUES = enumC4479fArr;
        $ENTRIES = AbstractC3328d.f(enumC4479fArr);
        Companion = new C4476e();
    }

    public EnumC4479f(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4479f valueOf(String str) {
        return (EnumC4479f) Enum.valueOf(EnumC4479f.class, str);
    }

    public static EnumC4479f[] values() {
        return (EnumC4479f[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
