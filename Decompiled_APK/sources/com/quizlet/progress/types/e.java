package com.quizlet.progress.types;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public final com.quizlet.progress.enums.a a;
    public final long b;
    public final long c;
    public final long d;
    public final com.quizlet.progress.enums.b e;

    public e(com.quizlet.progress.enums.a correctness, long j, long j2, long j3, com.quizlet.progress.enums.b type) {
        Intrinsics.checkNotNullParameter(correctness, "correctness");
        Intrinsics.checkNotNullParameter(type, "type");
        this.a = correctness;
        this.b = j;
        this.c = j2;
        this.d = j3;
        this.e = type;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return this.a == eVar.a && this.b == eVar.b && this.c == eVar.c && this.d == eVar.d && this.e == eVar.e;
    }

    public final int hashCode() {
        return this.e.hashCode() + d0.d(d0.d(d0.d(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d);
    }

    public final String toString() {
        return "StudiableAnswer(correctness=" + this.a + ", setId=" + this.b + ", termId=" + this.c + ", timestampMs=" + this.d + ", type=" + this.e + ")";
    }
}
