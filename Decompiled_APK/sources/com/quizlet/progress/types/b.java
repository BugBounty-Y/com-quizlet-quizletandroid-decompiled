package com.quizlet.progress.types;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final long a;
    public final long b;
    public final long c;
    public final ArrayList d;

    public b(long j, long j2, long j3, ArrayList answerHistories) {
        Intrinsics.checkNotNullParameter(answerHistories, "answerHistories");
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = answerHistories;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a == bVar.a && this.b == bVar.b && this.c == bVar.c && this.d.equals(bVar.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.d(d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AnswerSummary(containerId=");
        sb.append(this.a);
        sb.append(", itemId=");
        sb.append(this.b);
        sb.append(", date=");
        sb.append(this.c);
        sb.append(", answerHistories=");
        return AbstractC0147y.f(")", sb, this.d);
    }
}
