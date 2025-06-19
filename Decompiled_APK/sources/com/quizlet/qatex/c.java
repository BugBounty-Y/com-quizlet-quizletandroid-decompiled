package com.quizlet.qatex;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final String a;
    public final int b;
    public final float c;
    public final boolean d;

    public c(String text, int i, float f, boolean z) {
        Intrinsics.checkNotNullParameter(text, "text");
        this.a = text;
        this.b = i;
        this.c = f;
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && this.b == cVar.b && Float.compare(this.c, cVar.c) == 0 && this.d == cVar.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + android.support.v4.media.session.a.b(d0.b(this.b, this.a.hashCode() * 31, 31), this.c, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("QatexViewData(text=");
        sb.append(this.a);
        sb.append(", textColor=");
        sb.append(this.b);
        sb.append(", textSizePx=");
        sb.append(this.c);
        sb.append(", isResult=");
        return android.support.v4.media.session.a.o(")", sb, this.d);
    }
}
