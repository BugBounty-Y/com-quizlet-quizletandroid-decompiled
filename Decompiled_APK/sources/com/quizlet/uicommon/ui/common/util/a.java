package com.quizlet.uicommon.ui.common.util;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class a extends d {
    public boolean a;
    public int b;
    public boolean c;

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && this.b == aVar.b && this.c == aVar.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.b(this.b, Boolean.hashCode(this.a) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeMissedTerms(isMetered=");
        sb.append(this.a);
        sb.append(", missedTermCount=");
        sb.append(this.b);
        sb.append(", isPlus=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
