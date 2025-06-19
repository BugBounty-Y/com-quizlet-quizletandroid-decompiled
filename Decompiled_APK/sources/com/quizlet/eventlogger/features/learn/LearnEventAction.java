package com.quizlet.eventlogger.features.learn;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes2.dex */
public final class LearnEventAction {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ LearnEventAction[] $VALUES;
    public static final LearnEventAction a;
    public static final LearnEventAction b;
    public static final LearnEventAction c;
    public static final LearnEventAction d;
    public static final LearnEventAction e;
    public static final LearnEventAction f;
    public static final LearnEventAction g;
    public static final LearnEventAction h;
    public static final LearnEventAction i;
    public static final LearnEventAction j;
    public static final LearnEventAction k;
    public static final LearnEventAction l;
    public static final LearnEventAction m;
    public static final LearnEventAction n;
    public static final LearnEventAction o;

    @NotNull
    private final String value;

    static {
        LearnEventAction learnEventAction = new LearnEventAction("CLOSE_CLICKED", 0, "study_mode_back_button_clicked");
        a = learnEventAction;
        LearnEventAction learnEventAction2 = new LearnEventAction("LA_SETTINGS_TURN_OFF_PERSONALIZATION_CLICKED", 1, "tasks_escape_hatch_link_click");
        b = learnEventAction2;
        LearnEventAction learnEventAction3 = new LearnEventAction("LEARN_COMPLETION_CHECKPOINT_FINISH_LEARN_CLICKED", 2, "tasks_back_to_set_page_click");
        LearnEventAction learnEventAction4 = new LearnEventAction("LEARN_COMPLETION_CHECKPOINT_STUDY_AGAIN_CLICKED", 3, "tasks_restart_learn_task_sequence");
        LearnEventAction learnEventAction5 = new LearnEventAction("LEARN_ENDING_SCREEN_LOAD", 4, "tasks_non_plus_completion_checkpoint_screen_load");
        c = learnEventAction5;
        LearnEventAction learnEventAction6 = new LearnEventAction("LEARN_ROUND_SUMMARY_PLAY_AUDIO_CLICKED", 5, "tasks_round_checkpoint_audio_clicked");
        d = learnEventAction6;
        LearnEventAction learnEventAction7 = new LearnEventAction("LEARN_ROUND_SUMMARY_RESULTS", 6, "tasks_round_checkpoint_terms");
        e = learnEventAction7;
        LearnEventAction learnEventAction8 = new LearnEventAction("LEARN_ROUND_SUMMARY_SCREEN_LOAD", 7, "tasks_round_checkpoint_screen_load");
        f = learnEventAction8;
        LearnEventAction learnEventAction9 = new LearnEventAction("LEARN_ROUND_SUMMARY_STAR_CLICKED", 8, "tasks_round_checkpoint_star_clicked");
        g = learnEventAction9;
        LearnEventAction learnEventAction10 = new LearnEventAction("TURN_OFF_PERSONALIZATION_CONFIRMATION_CANCEL_CLICKED", 9, "tasks_skip_personalization_cancel_click");
        LearnEventAction learnEventAction11 = new LearnEventAction("TURN_OFF_PERSONALIZATION_CONFIRMATION_CONFIRM_CLICKED", 10, "tasks_skip_personalization_confirm_click");
        h = learnEventAction11;
        LearnEventAction learnEventAction12 = new LearnEventAction("GOAL_AND_PROGRESS_RESET", 11, "goal_and_progress_reset");
        i = learnEventAction12;
        LearnEventAction learnEventAction13 = new LearnEventAction("UNESCAPING_THE_HATCH", 12, "unescaping_the_hatch");
        j = learnEventAction13;
        LearnEventAction learnEventAction14 = new LearnEventAction("CLOSING_SETTING_SCREEN_BACK_TO_LEARN", 13, "closing_setting_screen_back_to_learn");
        k = learnEventAction14;
        LearnEventAction learnEventAction15 = new LearnEventAction("LEARN_MODE_SHUFFLE_OPTIONS_CHANGED", 14, "learn_mode_Shuffle_options_changed");
        LearnEventAction learnEventAction16 = new LearnEventAction("OPT_OUT_FLEXIBLE_LEARN_CLICKED", 15, "opt_out_flexible_learn_clicked");
        LearnEventAction learnEventAction17 = new LearnEventAction("OPT_OUT_FLEXIBLE_LEARN_CONFIRMED", 16, "opt_out_flexible_learn_confirmed");
        LearnEventAction learnEventAction18 = new LearnEventAction("OPT_OUT_FLEXIBLE_LEARN_CANCEL", 17, "opt_out_flexible_learn_cancel");
        LearnEventAction learnEventAction19 = new LearnEventAction("LOSING_MISSED_TERMS_WARNING_SHOWN", 18, "losing_missed_terms_warning_shown");
        l = learnEventAction19;
        LearnEventAction learnEventAction20 = new LearnEventAction("LOSING_MISSED_TERMS_CANCEL_CLICKED", 19, "losing_missed_terms_cancel_clicked");
        m = learnEventAction20;
        LearnEventAction learnEventAction21 = new LearnEventAction("LOSING_MISSED_TERMS_EXIT_CLICKED", 20, "losing_missed_terms_exit_clicked");
        n = learnEventAction21;
        LearnEventAction learnEventAction22 = new LearnEventAction("FOCUSED_LEARN_ONBOARDING_MODAL_SEEN", 21, "focused_learn_onboarding_modal_seen");
        o = learnEventAction22;
        LearnEventAction[] learnEventActionArr = {learnEventAction, learnEventAction2, learnEventAction3, learnEventAction4, learnEventAction5, learnEventAction6, learnEventAction7, learnEventAction8, learnEventAction9, learnEventAction10, learnEventAction11, learnEventAction12, learnEventAction13, learnEventAction14, learnEventAction15, learnEventAction16, learnEventAction17, learnEventAction18, learnEventAction19, learnEventAction20, learnEventAction21, learnEventAction22};
        $VALUES = learnEventActionArr;
        $ENTRIES = AbstractC3328d.f(learnEventActionArr);
    }

    private LearnEventAction(String str, int i2, String str2) {
        this.value = str2;
    }

    @NotNull
    public static a getEntries() {
        return $ENTRIES;
    }

    public static LearnEventAction valueOf(String str) {
        return (LearnEventAction) Enum.valueOf(LearnEventAction.class, str);
    }

    public static LearnEventAction[] values() {
        return (LearnEventAction[]) $VALUES.clone();
    }

    @NotNull
    public final String getValue() {
        return this.value;
    }
}
