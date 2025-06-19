package com.quizlet.remote.model.practicetests;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PracticeTestBody {
    public final String a;
    public final int b;
    public final PracticeTestConfiguration c;
    public final String d;
    public final QuestionBankMetadata e;
    public final QuestionCompatibility f;

    public PracticeTestBody(String questionBankUuid, int i, PracticeTestConfiguration configuration, String entryPoint, QuestionBankMetadata questionBankMetadata, QuestionCompatibility questionCompatibility) {
        Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
        Intrinsics.checkNotNullParameter(configuration, "configuration");
        Intrinsics.checkNotNullParameter(entryPoint, "entryPoint");
        Intrinsics.checkNotNullParameter(questionBankMetadata, "questionBankMetadata");
        Intrinsics.checkNotNullParameter(questionCompatibility, "questionCompatibility");
        this.a = questionBankUuid;
        this.b = i;
        this.c = configuration;
        this.d = entryPoint;
        this.e = questionBankMetadata;
        this.f = questionCompatibility;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PracticeTestBody)) {
            return false;
        }
        PracticeTestBody practiceTestBody = (PracticeTestBody) obj;
        return Intrinsics.b(this.a, practiceTestBody.a) && this.b == practiceTestBody.b && Intrinsics.b(this.c, practiceTestBody.c) && Intrinsics.b(this.d, practiceTestBody.d) && Intrinsics.b(this.e, practiceTestBody.e) && Intrinsics.b(this.f, practiceTestBody.f);
    }

    public final int hashCode() {
        return this.f.hashCode() + ((this.e.hashCode() + d0.e((this.c.hashCode() + d0.b(this.b, this.a.hashCode() * 31, 31)) * 31, 31, this.d)) * 31);
    }

    public final String toString() {
        return "PracticeTestBody(questionBankUuid=" + this.a + ", round=" + this.b + ", configuration=" + this.c + ", entryPoint=" + this.d + ", questionBankMetadata=" + this.e + ", questionCompatibility=" + this.f + ")";
    }
}
