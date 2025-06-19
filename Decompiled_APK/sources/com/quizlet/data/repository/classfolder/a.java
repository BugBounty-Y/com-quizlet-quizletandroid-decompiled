package com.quizlet.data.repository.classfolder;

/* loaded from: classes2.dex */
public final class a {
    public final long a;
    public final long b;

    public a(long j, long j2) {
        this.a = j;
        this.b = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && this.b == aVar.b;
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ClassFolderId(classId=");
        sb.append(this.a);
        sb.append(", folderId=");
        return android.support.v4.media.session.a.g(this.b, ")", sb);
    }
}
