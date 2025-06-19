package com.quizlet.quizletandroid.ui.startpage.nav2.screenstates;

/* loaded from: classes3.dex */
public final class t {
    public final int a;
    public final int b;

    public t(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof t)) {
            return false;
        }
        t tVar = (t) obj;
        return this.a == tVar.a && this.b == tVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoveIrrelevantRecommendation(indexToRemove=");
        sb.append(this.a);
        sb.append(", recsSectionNumber=");
        return android.support.v4.media.session.a.r(sb, this.b, ")");
    }
}
