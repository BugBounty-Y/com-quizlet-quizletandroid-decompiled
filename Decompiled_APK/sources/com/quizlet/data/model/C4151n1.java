package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.n1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4151n1 {
    public final Question a;
    public final X b;
    public final boolean c;

    public C4151n1(Question question, X x, boolean z) {
        Intrinsics.checkNotNullParameter(question, "question");
        this.a = question;
        this.b = x;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4151n1)) {
            return false;
        }
        C4151n1 c4151n1 = (C4151n1) obj;
        return Intrinsics.b(this.a, c4151n1.a) && Intrinsics.b(this.b, c4151n1.b) && this.c == c4151n1.c;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        X x = this.b;
        return Boolean.hashCode(this.c) + ((iHashCode + (x == null ? 0 : x.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("QuestionDetailsWithMetering(question=");
        sb.append(this.a);
        sb.append(", meteringInfo=");
        sb.append(this.b);
        sb.append(", isContentLimited=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
