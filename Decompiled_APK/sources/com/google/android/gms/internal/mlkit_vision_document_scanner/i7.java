package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import android.content.Intent;
import com.quizlet.explanations.questiondetail.data.QuestionDetailSetUpState;
import com.quizlet.explanations.questiondetail.ui.QuestionDetailActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class i7 {
    public static final /* synthetic */ int a = 0;

    public static Intent a(Context context, QuestionDetailSetUpState.WithId setUpState) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(setUpState, "setUpState");
        Intent intent = new Intent(context, (Class<?>) QuestionDetailActivity.class);
        intent.putExtra("EXTRA_QUESTION_DETAIL_SET_UP_STATE", setUpState);
        return intent;
    }
}
