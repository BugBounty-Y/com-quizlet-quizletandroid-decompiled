package com.quizlet.ui.models.webpage;

import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends b {
    public final String c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(String practiceTestUuid) {
        super("/practice-test/".concat(practiceTestUuid), R.string.app_name);
        Intrinsics.checkNotNullParameter(practiceTestUuid, "practiceTestUuid");
        this.c = practiceTestUuid;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof g) && Intrinsics.b(this.c, ((g) obj).c);
    }

    public final int hashCode() {
        return this.c.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("PracticeTestTakingWebPage(practiceTestUuid="), this.c, ")");
    }
}
