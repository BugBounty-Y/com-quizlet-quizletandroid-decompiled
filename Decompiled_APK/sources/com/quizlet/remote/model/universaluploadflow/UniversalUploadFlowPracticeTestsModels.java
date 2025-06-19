package com.quizlet.remote.model.universaluploadflow;

import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class UniversalUploadFlowPracticeTestsModels {
    public final List a;
    public final List b;

    public UniversalUploadFlowPracticeTestsModels(List document, List qbp) {
        Intrinsics.checkNotNullParameter(document, "document");
        Intrinsics.checkNotNullParameter(qbp, "qbp");
        this.a = document;
        this.b = qbp;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof UniversalUploadFlowPracticeTestsModels)) {
            return false;
        }
        UniversalUploadFlowPracticeTestsModels universalUploadFlowPracticeTestsModels = (UniversalUploadFlowPracticeTestsModels) obj;
        return Intrinsics.b(this.a, universalUploadFlowPracticeTestsModels.a) && Intrinsics.b(this.b, universalUploadFlowPracticeTestsModels.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "UniversalUploadFlowPracticeTestsModels(document=" + this.a + ", qbp=" + this.b + ")";
    }
}
