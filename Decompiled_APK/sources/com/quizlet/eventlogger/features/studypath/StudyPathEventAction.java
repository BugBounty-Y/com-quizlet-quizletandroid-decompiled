package com.quizlet.eventlogger.features.studypath;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes2.dex */
public final class StudyPathEventAction {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ StudyPathEventAction[] $VALUES;

    @NotNull
    private final String value;

    static {
        StudyPathEventAction[] studyPathEventActionArr = {new StudyPathEventAction("GOAL_INTAKE_DID_ANSWER_QUESTION", 0, "study_path_goal_intake_did_answer_question"), new StudyPathEventAction("TAP_SKIP_STUDY_PATH", 1, "study_path_did_tap_skip_results_button"), new StudyPathEventAction("TAP_DISMISS_STUDY_PATH", 2, "study_path_did_tap_dismiss_button"), new StudyPathEventAction("INTRO_SCREEN_CONTINUE_CLICK", 3, "study_paths_intro_screen_continue_button_click"), new StudyPathEventAction("STEPPER_VIEW_LOAD", 4, "study_paths_stepper_view_load"), new StudyPathEventAction("UNDERSTANDING_GOAL_AVAILABLE", 5, "understanding_goal_available"), new StudyPathEventAction("UNDERSTANDING_GOAL_UNAVAILABLE", 6, "understanding_goal_unavailable")};
        $VALUES = studyPathEventActionArr;
        $ENTRIES = AbstractC3328d.f(studyPathEventActionArr);
    }

    private StudyPathEventAction(String str, int i, String str2) {
        this.value = str2;
    }

    @NotNull
    public static a getEntries() {
        return $ENTRIES;
    }

    public static StudyPathEventAction valueOf(String str) {
        return (StudyPathEventAction) Enum.valueOf(StudyPathEventAction.class, str);
    }

    public static StudyPathEventAction[] values() {
        return (StudyPathEventAction[]) $VALUES.clone();
    }

    @NotNull
    public final String getValue() {
        return this.value;
    }
}
