package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class B implements InterfaceC4315x {
    public final String a;
    public final int b;
    public final boolean c;

    public B(String questionId, int i, boolean z) {
        Intrinsics.checkNotNullParameter(questionId, "questionId");
        this.a = questionId;
        this.b = i;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof B)) {
            return false;
        }
        B b = (B) obj;
        return Intrinsics.b(this.a, b.a) && this.b == b.b && this.c == b.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + androidx.compose.animation.d0.b(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("QuestionClicked(questionId=");
        sb.append(this.a);
        sb.append(", index=");
        sb.append(this.b);
        sb.append(", isRecommended=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
