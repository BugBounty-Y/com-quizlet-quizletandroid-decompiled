package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import kotlin.Metadata;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class UpdateGradedAnswerBody {
    public final boolean a;

    public UpdateGradedAnswerBody(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof UpdateGradedAnswerBody) && this.a == ((UpdateGradedAnswerBody) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("UpdateGradedAnswerBody(excluded="), this.a);
    }
}
