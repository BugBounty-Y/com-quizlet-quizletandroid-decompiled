package com.quizlet.quizletandroid.ui.studymodes.testmode.models;

import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class t implements b {
    public final com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.g a;

    public t(com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.g questionTuple) {
        Intrinsics.checkNotNullParameter(questionTuple, "questionTuple");
        Intrinsics.checkNotNullParameter("test_mode_answers_id", DBSessionFields.Names.ITEM_ID);
        this.a = questionTuple;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof t) {
            return Intrinsics.b(this.a, ((t) obj).a);
        }
        return false;
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return "test_mode_answers_id";
    }

    public final int hashCode() {
        return (this.a.hashCode() * 31) - 1993873516;
    }

    public final String toString() {
        return "TestAnswersItem(questionTuple=" + this.a + ", itemId=test_mode_answers_id)";
    }
}
