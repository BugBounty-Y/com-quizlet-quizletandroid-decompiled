package com.quizlet.remote.model.universaluploadflow;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class UniversalUploadFlowPracticeTestsStatus {
    public final String a;
    public final int b;
    public final String c;

    public UniversalUploadFlowPracticeTestsStatus(String id, int i, String str) {
        Intrinsics.checkNotNullParameter(id, "id");
        this.a = id;
        this.b = i;
        this.c = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof UniversalUploadFlowPracticeTestsStatus)) {
            return false;
        }
        UniversalUploadFlowPracticeTestsStatus universalUploadFlowPracticeTestsStatus = (UniversalUploadFlowPracticeTestsStatus) obj;
        return Intrinsics.b(this.a, universalUploadFlowPracticeTestsStatus.a) && this.b == universalUploadFlowPracticeTestsStatus.b && Intrinsics.b(this.c, universalUploadFlowPracticeTestsStatus.c);
    }

    public final int hashCode() {
        int iB = d0.b(this.b, this.a.hashCode() * 31, 31);
        String str = this.c;
        return iB + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UniversalUploadFlowPracticeTestsStatus(id=");
        sb.append(this.a);
        sb.append(", status=");
        sb.append(this.b);
        sb.append(", error=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
