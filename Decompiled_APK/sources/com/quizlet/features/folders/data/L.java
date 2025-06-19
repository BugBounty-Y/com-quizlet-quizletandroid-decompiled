package com.quizlet.features.folders.data;

/* loaded from: classes3.dex */
public final class L implements InterfaceC4315x {
    public final long a;
    public final int b;
    public final boolean c;

    public L(boolean z, long j, int i) {
        this.a = j;
        this.b = i;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof L)) {
            return false;
        }
        L l = (L) obj;
        return this.a == l.a && this.b == l.b && this.c == l.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + androidx.compose.animation.d0.b(this.b, Long.hashCode(this.a) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudySetClicked(setId=");
        sb.append(this.a);
        sb.append(", index=");
        sb.append(this.b);
        sb.append(", isRecommended=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
