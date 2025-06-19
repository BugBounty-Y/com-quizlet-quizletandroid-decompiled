package com.quizlet.upgrade.data;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class q implements com.quizlet.baserecyclerview.a {
    public final int a;
    public final int b;
    public final int c;
    public final int d;

    public q(int i, int i2, int i3) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof q)) {
            return false;
        }
        q qVar = (q) obj;
        return this.a == qVar.a && this.b == qVar.b && this.c == qVar.c;
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return Integer.valueOf(this.d);
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + d0.b(this.b, Integer.hashCode(this.a) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UpgradeFeature(iconRes=");
        sb.append(this.a);
        sb.append(", titleRes=");
        sb.append(this.b);
        sb.append(", descriptionRes=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }
}
