package com.google.firebase;

import android.content.Context;
import android.content.res.Resources;
import android.text.SpannableString;
import com.quizlet.data.model.A0;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class b {
    public static final /* synthetic */ int a = 0;

    public static final com.quizlet.uicommon.ui.common.util.e a(com.quizlet.uicommon.ui.common.util.d dVar, Context context, boolean z) throws Resources.NotFoundException {
        String string;
        SpannableString spannableString;
        int i;
        Intrinsics.checkNotNullParameter(dVar, "<this>");
        Intrinsics.checkNotNullParameter(context, "context");
        SpannableString spannableString2 = new SpannableString("");
        A0 a0 = A0.b;
        if (dVar instanceof com.quizlet.uicommon.ui.common.util.b) {
            string = context.getString(R.string.test_next_action_take_new_test_title);
            SpannableString spannableString3 = new SpannableString(context.getString(R.string.test_next_action_take_new_test_description));
            i = z ? R.drawable.ic_study_test_white : R.drawable.ic_study_test;
            if (((com.quizlet.uicommon.ui.common.util.b) dVar).a) {
                a0 = A0.a;
            }
            spannableString = spannableString3;
        } else if (!dVar.equals(com.quizlet.uicommon.ui.common.util.c.a) && (dVar instanceof com.quizlet.uicommon.ui.common.util.a)) {
            Resources resources = context.getResources();
            com.quizlet.uicommon.ui.common.util.a aVar = (com.quizlet.uicommon.ui.common.util.a) dVar;
            int i2 = aVar.b;
            String quantityString = resources.getQuantityString(R.plurals.test_next_action_practice_missed_terms_title, i2, Integer.valueOf(i2));
            if (aVar.a) {
                a0 = A0.a;
            }
            i = R.drawable.ic_study_learn_white;
            spannableString = spannableString2;
            string = quantityString;
        } else {
            string = context.getString(R.string.test_next_action_flashcards_title);
            spannableString = new SpannableString(context.getString(R.string.test_next_action_flashcards_description));
            i = R.drawable.ic_study_flashcards;
        }
        return new com.quizlet.uicommon.ui.common.util.e(string, spannableString, i, a0);
    }
}
