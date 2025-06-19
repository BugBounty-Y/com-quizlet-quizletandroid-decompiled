package com.quizlet.explanations.myexplanations.data;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class p implements com.quizlet.baserecyclerview.a, a {
    public final String a;
    public final String b;
    public final String c;
    public final int d;
    public final boolean e;
    public final long f;
    public final String g;

    public p(int i, long j, String id, String prompt, String slug, boolean z) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(slug, "slug");
        this.a = id;
        this.b = prompt;
        this.c = slug;
        this.d = i;
        this.e = z;
        this.f = j;
        this.g = AbstractC0147y.d("question-", id);
    }

    @Override // com.quizlet.explanations.myexplanations.data.a
    public final long a() {
        return this.f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof p)) {
            return false;
        }
        p pVar = (p) obj;
        return Intrinsics.b(this.a, pVar.a) && Intrinsics.b(this.b, pVar.b) && Intrinsics.b(this.c, pVar.c) && this.d == pVar.d && this.e == pVar.e && this.f == pVar.f;
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return this.g;
    }

    public final int hashCode() {
        return Long.hashCode(this.f) + d0.g(d0.b(this.d, d0.e(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31), 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MyExplanationsQuestionItem(id=");
        sb.append(this.a);
        sb.append(", prompt=");
        sb.append(this.b);
        sb.append(", slug=");
        sb.append(this.c);
        sb.append(", subjectStringRes=");
        sb.append(this.d);
        sb.append(", isPlusEnabled=");
        sb.append(this.e);
        sb.append(", timestampSec=");
        return android.support.v4.media.session.a.g(this.f, ")", sb);
    }
}
