package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class QuestionPrompt {
    public final String a;
    public final SimpleImage b;

    public QuestionPrompt(String str, SimpleImage simpleImage) {
        this.a = str;
        this.b = simpleImage;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof QuestionPrompt)) {
            return false;
        }
        QuestionPrompt questionPrompt = (QuestionPrompt) obj;
        return Intrinsics.b(this.a, questionPrompt.a) && Intrinsics.b(this.b, questionPrompt.b);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        SimpleImage simpleImage = this.b;
        return iHashCode + (simpleImage != null ? simpleImage.hashCode() : 0);
    }

    public final String toString() {
        return "QuestionPrompt(text=" + this.a + ", image=" + this.b + ")";
    }
}
