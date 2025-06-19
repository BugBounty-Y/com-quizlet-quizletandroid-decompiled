package com.quizlet.quizletandroid.util;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class l {
    public final int a;
    public final int b;
    public final int c;
    public final int d;

    public l(int i, int i2, int i3, int i4) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = i4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof l)) {
            return false;
        }
        l lVar = (l) obj;
        return this.a == lVar.a && this.b == lVar.b && this.c == lVar.c && this.d == lVar.d;
    }

    public final int hashCode() {
        return Integer.hashCode(this.d) + d0.b(this.c, d0.b(this.b, Integer.hashCode(this.a) * 31, 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StorageData(imageSize=");
        sb.append(this.a);
        sb.append(", audioSize=");
        sb.append(this.b);
        sb.append(", dbSize=");
        sb.append(this.c);
        sb.append(", otherSize=");
        return android.support.v4.media.session.a.r(sb, this.d, ")");
    }
}
