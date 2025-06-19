package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class CopyPracticeTestBody {
    public final String a;
    public final String b;

    public CopyPracticeTestBody(String questionBankUuid, String practiceTestUuid) {
        Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
        Intrinsics.checkNotNullParameter(practiceTestUuid, "practiceTestUuid");
        this.a = questionBankUuid;
        this.b = practiceTestUuid;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof CopyPracticeTestBody)) {
            return false;
        }
        CopyPracticeTestBody copyPracticeTestBody = (CopyPracticeTestBody) obj;
        return Intrinsics.b(this.a, copyPracticeTestBody.a) && Intrinsics.b(this.b, copyPracticeTestBody.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CopyPracticeTestBody(questionBankUuid=");
        sb.append(this.a);
        sb.append(", practiceTestUuid=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
