package com.quizlet.ui.models.webpage;

import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h extends b {
    public final String c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(String questionBankUuid) {
        super("/test-questions/" + questionBankUuid, R.string.app_name);
        Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
        this.c = questionBankUuid;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof h) && Intrinsics.b(this.c, ((h) obj).c);
    }

    public final int hashCode() {
        return this.c.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("PracticeTestWebPage(questionBankUuid="), this.c, ")");
    }
}
