package com.quizlet.upgrade.data;

import com.quizlet.quizletandroid.R;
import java.util.Calendar;
import java.util.Date;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class p {
    public static final q a = new q(2131231326, R.string.magic_notes_value_prop_title, R.string.magic_notes_value_prop_description);
    public static final q b = new q(R.drawable.ic_brand_solutions_plus, R.string.expert_explanations_title, R.string.expert_explanations_description);
    public static final q c = new q(R.drawable.ic_brand_multiple_choice_plus, R.string.study_smarter_title, R.string.study_smarter_description);
    public static final q d = new q(R.drawable.ic_brand_creation_toolkit_plus, R.string.customized_sets_title, R.string.customized_sets_description);
    public static final q e = new q(R.drawable.ic_brand_no_ads_plus, R.string.student_ads_value_prop_title, R.string.student_ads_value_prop_description);
    public static final q f = new q(R.drawable.ic_brand_track_progress_plus, R.string.watch_student_progress_title, R.string.watch_student_progress_description);
    public static final q g = new q(R.drawable.ic_brand_custom_teams_plus, R.string.customize_quizlet_live_title, R.string.customize_quizlet_live_description);
    public static final q h = new q(R.drawable.ic_brand_multiple_choice_plus, R.string.teacher_learn_test_value_prop_title, R.string.teacher_learn_test_value_prop_description);
    public static final q i = new q(R.drawable.ic_brand_no_ads_plus, R.string.teacher_ads_value_prop_title, R.string.teacher_ads_value_prop_description);

    public static com.quizlet.qutils.string.b a(Calendar calendar, int i2, int i3, String datePattern) {
        Intrinsics.checkNotNullParameter(calendar, "<this>");
        Calendar calendar2 = Calendar.getInstance();
        Intrinsics.checkNotNullExpressionValue(calendar2, "getInstance(...)");
        calendar2.setTime(calendar.getTime());
        calendar2.add(i2, i3);
        Date date = calendar2.getTime();
        Intrinsics.checkNotNullExpressionValue(date, "getTime(...)");
        Intrinsics.checkNotNullParameter(datePattern, "datePattern");
        Intrinsics.checkNotNullParameter(date, "date");
        return new com.quizlet.qutils.string.b(datePattern, date);
    }
}
