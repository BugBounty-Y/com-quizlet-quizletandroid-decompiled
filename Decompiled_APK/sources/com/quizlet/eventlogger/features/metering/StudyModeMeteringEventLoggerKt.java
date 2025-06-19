package com.quizlet.eventlogger.features.metering;

import com.quizlet.shared.enums.MeteredEventType$Companion;
import com.quizlet.shared.enums.h;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class StudyModeMeteringEventLoggerKt {

    @NotNull
    private static final String LEARN_REMAINING_ROUNDS_TOAST_DISMISS = "learn_remaining_rounds_toast_dismiss";

    @NotNull
    private static final String LEARN_REMAINING_ROUNDS_TOAST_IMPRESSION = "learn_remaining_rounds_toast_impression";

    @NotNull
    private static final String LEARN_REMAINING_ROUNDS_TOAST_UPGRADE = "learn_remaining_rounds_toast_upgrade";

    @NotNull
    private static final String LEARN_ROUND_COMPLETE_PAYWALL_DISMISS = "learn_remaining_rounds_paywall_dismiss";

    @NotNull
    private static final String LEARN_ROUND_COMPLETE_PAYWALL_IMPRESSION = "learn_remaining_rounds_paywall_impression";

    @NotNull
    private static final String LEARN_ROUND_COMPLETE_PAYWALL_PRIMARY_ACTION = "learn_round_complete_paywall_primary_action";

    @NotNull
    private static final String LEARN_ROUND_COMPLETE_PAYWALL_SECONDARY_ACTION = "learn_round_complete_paywall_secondary_action";

    @NotNull
    private static final String METER_OVERRIDDEN_FOR_TEACHER_SET = "meter_overriden_for_teacher_set";

    @NotNull
    private static final String SET_PAGE_PAYWALL_LOCK_IMPRESSION = "set_page_paywall_lock_impression";

    @NotNull
    private static final String TEST_REMAINING_ATTEMPTS_TOAST_DISMISS = "test_remaining_attempts_toast_dismiss";

    @NotNull
    private static final String TEST_REMAINING_ATTEMPTS_TOAST_IMPRESSION = "test_remaining_attempts_toast_impression";

    @NotNull
    private static final String TEST_REMAINING_ATTEMPTS_TOAST_UPGRADE = "test_remaining_attempts_toast_upgrade";

    @NotNull
    private static final String TEST_RESULTS_PAYWALL_BUTTON_IMPRESSED = "test_results_paywall_button_impressed";

    @NotNull
    private static final String TEST_ROUND_COMPLETE_PAYWALL_DISMISS = "test_remaining_attempts_paywall_dismiss";

    @NotNull
    private static final String TEST_ROUND_COMPLETE_PAYWALL_IMPRESSION = "test_remaining_attempts_paywall_impression";

    @NotNull
    private static final String TEST_ROUND_COMPLETE_PAYWALL_PRIMARY_ACTION = "test_round_complete_paywall_primary_action";

    @NotNull
    private static final String TEST_ROUND_COMPLETE_PAYWALL_SECONDARY_ACTION = "test_round_complete_paywall_secondary_action";

    @Metadata
    public /* synthetic */ class WhenMappings {
        static {
            int[] iArr = new int[h.values().length];
            try {
                iArr[0] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                MeteredEventType$Companion meteredEventType$Companion = h.Companion;
                iArr[1] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                MeteredEventType$Companion meteredEventType$Companion2 = h.Companion;
                iArr[2] = 3;
            } catch (NoSuchFieldError unused3) {
            }
        }
    }
}
