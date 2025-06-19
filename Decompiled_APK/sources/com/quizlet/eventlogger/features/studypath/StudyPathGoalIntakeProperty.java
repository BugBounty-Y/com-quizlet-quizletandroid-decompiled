package com.quizlet.eventlogger.features.studypath;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes2.dex */
public final class StudyPathGoalIntakeProperty {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ StudyPathGoalIntakeProperty[] $VALUES;

    @NotNull
    private final String value;

    static {
        StudyPathGoalIntakeProperty[] studyPathGoalIntakePropertyArr = {new StudyPathGoalIntakeProperty("DESIRED_GOAL", 0, "goalKnowledgeLevel"), new StudyPathGoalIntakeProperty("CURRENT_KNOWLEDGE", 1, "currentKnowledgeLevel")};
        $VALUES = studyPathGoalIntakePropertyArr;
        $ENTRIES = AbstractC3328d.f(studyPathGoalIntakePropertyArr);
    }

    private StudyPathGoalIntakeProperty(String str, int i, String str2) {
        this.value = str2;
    }

    @NotNull
    public static a getEntries() {
        return $ENTRIES;
    }

    public static StudyPathGoalIntakeProperty valueOf(String str) {
        return (StudyPathGoalIntakeProperty) Enum.valueOf(StudyPathGoalIntakeProperty.class, str);
    }

    public static StudyPathGoalIntakeProperty[] values() {
        return (StudyPathGoalIntakeProperty[]) $VALUES.clone();
    }

    @NotNull
    public final String getValue() {
        return this.value;
    }
}
