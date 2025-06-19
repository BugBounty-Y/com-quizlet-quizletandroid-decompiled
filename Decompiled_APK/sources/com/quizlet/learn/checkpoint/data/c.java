package com.quizlet.learn.checkpoint.data;

/* loaded from: classes3.dex */
public final class c {
    public final int a;
    public final int b;

    public c(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && this.b == cVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LearnProgressBarSummaryState(numCompleted=");
        sb.append(this.a);
        sb.append(", numTotal=");
        return android.support.v4.media.session.a.r(sb, this.b, ")");
    }
}
