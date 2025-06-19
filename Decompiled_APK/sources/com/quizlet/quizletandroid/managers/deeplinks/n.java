package com.quizlet.quizletandroid.managers.deeplinks;

import android.app.TaskStackBuilder;
import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3705q4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.i7;
import com.quizlet.explanations.questiondetail.data.QuestionDetailSetUpState;
import com.quizlet.explanations.questiondetail.ui.QuestionDetailActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n extends AbstractC3705q4 {
    public static final String b;
    public final String a;

    static {
        String simpleName = n.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        b = simpleName;
    }

    public n(String questionId) {
        Intrinsics.checkNotNullParameter(questionId, "questionId");
        this.a = questionId;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        String str = QuestionDetailActivity.t;
        Intent[] intents = TaskStackBuilder.create(context).addNextIntentWithParentStack(i7.a(context, new QuestionDetailSetUpState.WithId(this.a))).getIntents();
        Intrinsics.checkNotNullExpressionValue(intents, "getIntents(...)");
        return intents;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof n) && Intrinsics.b(this.a, ((n) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final String identity() {
        return b;
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("ExplanationsQuestionDeepLink(questionId="), this.a, ")");
    }
}
