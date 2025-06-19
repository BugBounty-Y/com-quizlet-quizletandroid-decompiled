package com.quizlet.features.match.data;

import com.google.android.gms.internal.mlkit_vision_barcode.O6;

/* loaded from: classes3.dex */
public final class c0 extends O6 {
    public final int b;
    public final int c;

    public c0(int i, int i2) {
        this.b = i;
        this.c = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c0)) {
            return false;
        }
        c0 c0Var = (c0) obj;
        return this.b == c0Var.b && this.c == c0Var.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + (Integer.hashCode(this.b) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StandardMatchData(cardIndexOne=");
        sb.append(this.b);
        sb.append(", cardIndexTwo=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }
}
