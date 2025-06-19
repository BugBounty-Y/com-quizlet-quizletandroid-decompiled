package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PracticeTestRedirect {
    public final String a;
    public final String b;

    public PracticeTestRedirect(String destination, String questionBankUuid) {
        Intrinsics.checkNotNullParameter(destination, "destination");
        Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
        this.a = destination;
        this.b = questionBankUuid;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PracticeTestRedirect)) {
            return false;
        }
        PracticeTestRedirect practiceTestRedirect = (PracticeTestRedirect) obj;
        return Intrinsics.b(this.a, practiceTestRedirect.a) && Intrinsics.b(this.b, practiceTestRedirect.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestRedirect(destination=");
        sb.append(this.a);
        sb.append(", questionBankUuid=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
