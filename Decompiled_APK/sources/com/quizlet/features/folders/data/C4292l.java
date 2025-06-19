package com.quizlet.features.folders.data;

/* renamed from: com.quizlet.features.folders.data.l, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4292l implements InterfaceC4315x {
    public final long a;
    public final int b;
    public final boolean c;

    public C4292l(boolean z, long j, int i) {
        this.a = j;
        this.b = i;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4292l)) {
            return false;
        }
        C4292l c4292l = (C4292l) obj;
        return this.a == c4292l.a && this.b == c4292l.b && this.c == c4292l.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + androidx.compose.animation.d0.b(this.b, Long.hashCode(this.a) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FolderClicked(folderId=");
        sb.append(this.a);
        sb.append(", index=");
        sb.append(this.b);
        sb.append(", isRecommended=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
