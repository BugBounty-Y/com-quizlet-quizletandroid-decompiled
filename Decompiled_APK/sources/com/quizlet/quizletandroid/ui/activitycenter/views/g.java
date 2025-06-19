package com.quizlet.quizletandroid.ui.activitycenter.views;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class g {
    public final int a;
    public final int b;
    public final int c;

    public g(int i, int i2, int i3) {
        this.a = i;
        this.b = i2;
        this.c = i3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return this.a == gVar.a && this.b == gVar.b && this.c == gVar.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + d0.b(this.b, Integer.hashCode(this.a) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Resources(defaultBackgroundRes=");
        sb.append(this.a);
        sb.append(", countViewDefaultWidth=");
        sb.append(this.b);
        sb.append(", countViewDefaultWidth9Plus=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }
}
