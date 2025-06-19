package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_document_scanner.F6;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class Question extends F6 {
    public final long a;
    public final String b;
    public final String c;
    public final String d;
    public final List e;
    public final QuestionPrompt f;
    public final Integer g;
    public final String h;
    public final List i;

    public Question(long j, String slug, String mediaExerciseId, String questionUuid, List subjects, QuestionPrompt prompt, Integer num, String str, List solutions) {
        Intrinsics.checkNotNullParameter(slug, "slug");
        Intrinsics.checkNotNullParameter(mediaExerciseId, "mediaExerciseId");
        Intrinsics.checkNotNullParameter(questionUuid, "questionUuid");
        Intrinsics.checkNotNullParameter(subjects, "subjects");
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(solutions, "solutions");
        this.a = j;
        this.b = slug;
        this.c = mediaExerciseId;
        this.d = questionUuid;
        this.e = subjects;
        this.f = prompt;
        this.g = num;
        this.h = str;
        this.i = solutions;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Question)) {
            return false;
        }
        Question question = (Question) obj;
        return this.a == question.a && Intrinsics.b(this.b, question.b) && Intrinsics.b(this.c, question.c) && Intrinsics.b(this.d, question.d) && Intrinsics.b(this.e, question.e) && Intrinsics.b(this.f, question.f) && Intrinsics.b(this.g, question.g) && Intrinsics.b(this.h, question.h) && Intrinsics.b(this.i, question.i);
    }

    public final int hashCode() {
        int iHashCode = (this.f.hashCode() + androidx.compose.animation.d0.f(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e)) * 31;
        Integer num = this.g;
        int iHashCode2 = (iHashCode + (num == null ? 0 : num.hashCode())) * 31;
        String str = this.h;
        return this.i.hashCode() + ((iHashCode2 + (str != null ? str.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Question(id=");
        sb.append(this.a);
        sb.append(", slug=");
        sb.append(this.b);
        sb.append(", mediaExerciseId=");
        sb.append(this.c);
        sb.append(", questionUuid=");
        sb.append(this.d);
        sb.append(", subjects=");
        sb.append(this.e);
        sb.append(", prompt=");
        sb.append(this.f);
        sb.append(", answersCount=");
        sb.append(this.g);
        sb.append(", webUrl=");
        sb.append(this.h);
        sb.append(", solutions=");
        return android.support.v4.media.session.a.n(")", sb, this.i);
    }
}
