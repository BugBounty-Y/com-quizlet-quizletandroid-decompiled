package com.quizlet.learn.data;

import androidx.compose.animation.d0;
import com.quizlet.studiablemodels.StudiableStep;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class O {
    public final StudiableStep a;
    public final int b;
    public final boolean c;

    public O(StudiableStep studiableStep, int i, boolean z) {
        Intrinsics.checkNotNullParameter(studiableStep, "studiableStep");
        this.a = studiableStep;
        this.b = i;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof O)) {
            return false;
        }
        O o = (O) obj;
        return Intrinsics.b(this.a, o.a) && this.b == o.b && this.c == o.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.b(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("NextPromptData(studiableStep=");
        sb.append(this.a);
        sb.append(", size=");
        sb.append(this.b);
        sb.append(", didMissQuestionRecently=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
