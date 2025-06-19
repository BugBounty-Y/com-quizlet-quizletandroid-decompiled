package com.quizlet.explanations.navigation;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_document_scanner.i7;
import com.quizlet.explanations.questiondetail.data.QuestionDetailSetUpState;
import com.quizlet.explanations.questiondetail.ui.QuestionDetailActivity;
import com.quizlet.features.infra.navigation.h;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public final class a implements h {
    public final Context a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.h
    public final void E(String questionUuId) {
        Intrinsics.checkNotNullParameter(questionUuId, "questionUuId");
        QuestionDetailSetUpState.WithId withId = new QuestionDetailSetUpState.WithId(questionUuId);
        String str = QuestionDetailActivity.t;
        Context context = this.a;
        context.startActivity(i7.a(context, withId));
    }
}
