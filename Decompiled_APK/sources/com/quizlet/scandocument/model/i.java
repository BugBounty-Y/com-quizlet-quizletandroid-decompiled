package com.quizlet.scandocument.model;

/* loaded from: classes3.dex */
public final class i {
    public final int a;
    public final int b;

    public i(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a == iVar.a && this.b == iVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("OcrPoint(x=");
        sb.append(this.a);
        sb.append(", y=");
        return android.support.v4.media.session.a.r(sb, this.b, ")");
    }
}
