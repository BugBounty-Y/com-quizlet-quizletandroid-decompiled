package com.quizlet.features.practicetest.results.data;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class y {
    public final int a;
    public final int b;
    public final int c;
    public final int d;

    public y(int i, int i2, int i3, int i4) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = i4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof y)) {
            return false;
        }
        y yVar = (y) obj;
        return this.a == yVar.a && this.b == yVar.b && this.c == yVar.c && this.d == yVar.d;
    }

    public final int hashCode() {
        return Integer.hashCode(this.d) + d0.b(this.c, d0.b(this.b, Integer.hashCode(this.a) * 31, 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ResultsScore(resMessageId=");
        sb.append(this.a);
        sb.append(", scorePercentage=");
        sb.append(this.b);
        sb.append(", correctCount=");
        sb.append(this.c);
        sb.append(", totalCount=");
        return android.support.v4.media.session.a.r(sb, this.d, ")");
    }
}
