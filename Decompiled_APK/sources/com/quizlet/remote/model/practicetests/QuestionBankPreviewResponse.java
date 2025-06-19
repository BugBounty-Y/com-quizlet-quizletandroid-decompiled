package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class QuestionBankPreviewResponse {
    public final List a;
    public final List b;

    public QuestionBankPreviewResponse(List questionBankPreview, List entitlementData) {
        Intrinsics.checkNotNullParameter(questionBankPreview, "questionBankPreview");
        Intrinsics.checkNotNullParameter(entitlementData, "entitlementData");
        this.a = questionBankPreview;
        this.b = entitlementData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof QuestionBankPreviewResponse)) {
            return false;
        }
        QuestionBankPreviewResponse questionBankPreviewResponse = (QuestionBankPreviewResponse) obj;
        return Intrinsics.b(this.a, questionBankPreviewResponse.a) && Intrinsics.b(this.b, questionBankPreviewResponse.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "QuestionBankPreviewResponse(questionBankPreview=" + this.a + ", entitlementData=" + this.b + ")";
    }

    public QuestionBankPreviewResponse(List list, List list2, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? K.a : list, (i & 2) != 0 ? K.a : list2);
    }
}
