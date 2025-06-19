package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_document_scanner.F6;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class C0 extends F6 implements B0 {
    public final long a;
    public final String b;
    public final String c;
    public final String d;
    public final List e;
    public final long f;
    public final String g;
    public final String h;

    public C0(long j, String slug, String mediaExerciseId, String questionUuid, List subjects, long j2, String prompt) {
        Intrinsics.checkNotNullParameter(slug, "slug");
        Intrinsics.checkNotNullParameter(mediaExerciseId, "mediaExerciseId");
        Intrinsics.checkNotNullParameter(questionUuid, "questionUuid");
        Intrinsics.checkNotNullParameter(subjects, "subjects");
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        this.a = j;
        this.b = slug;
        this.c = mediaExerciseId;
        this.d = questionUuid;
        this.e = subjects;
        this.f = j2;
        this.g = prompt;
        this.h = mediaExerciseId;
    }

    @Override // com.quizlet.data.model.B0
    public final long a() {
        return this.f;
    }

    @Override // com.quizlet.data.model.B0
    public final int b() {
        return 16;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0)) {
            return false;
        }
        C0 c0 = (C0) obj;
        return this.a == c0.a && Intrinsics.b(this.b, c0.b) && Intrinsics.b(this.c, c0.c) && Intrinsics.b(this.d, c0.d) && Intrinsics.b(this.e, c0.e) && this.f == c0.f && Intrinsics.b(this.g, c0.g);
    }

    @Override // com.quizlet.data.model.B0
    public final String getItemId() {
        return this.h;
    }

    public final int hashCode() {
        return this.g.hashCode() + androidx.compose.animation.d0.d(androidx.compose.animation.d0.f(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MyExplanationsQuestion(id=");
        sb.append(this.a);
        sb.append(", slug=");
        sb.append(this.b);
        sb.append(", mediaExerciseId=");
        sb.append(this.c);
        sb.append(", questionUuid=");
        sb.append(this.d);
        sb.append(", subjects=");
        sb.append(this.e);
        sb.append(", timestampSec=");
        sb.append(this.f);
        sb.append(", prompt=");
        return android.support.v4.media.session.a.t(sb, this.g, ")");
    }
}
