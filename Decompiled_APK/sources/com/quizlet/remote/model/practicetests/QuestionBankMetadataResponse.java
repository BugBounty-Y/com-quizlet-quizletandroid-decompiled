package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class QuestionBankMetadataResponse {
    public final Long a;

    public QuestionBankMetadataResponse(Long l) {
        this.a = l;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof QuestionBankMetadataResponse) && Intrinsics.b(this.a, ((QuestionBankMetadataResponse) obj).a);
    }

    public final int hashCode() {
        Long l = this.a;
        if (l == null) {
            return 0;
        }
        return l.hashCode();
    }

    public final String toString() {
        return "QuestionBankMetadataResponse(setId=" + this.a + ")";
    }

    public /* synthetic */ QuestionBankMetadataResponse(Long l, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : l);
    }
}
