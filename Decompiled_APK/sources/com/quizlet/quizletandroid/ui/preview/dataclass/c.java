package com.quizlet.quizletandroid.ui.preview.dataclass;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final long a;
    public final String b;
    public final String c;
    public final String d;

    public c(long j, String word, String str, String str2) {
        Intrinsics.checkNotNullParameter(word, "word");
        this.a = j;
        this.b = word;
        this.c = str;
        this.d = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && Intrinsics.b(this.b, cVar.b) && Intrinsics.b(this.c, cVar.c) && Intrinsics.b(this.d, cVar.d);
    }

    public final int hashCode() {
        int iE = d0.e(Long.hashCode(this.a) * 31, 31, this.b);
        String str = this.c;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.d;
        return iHashCode + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PreviewTerm(id=");
        sb.append(this.a);
        sb.append(", word=");
        sb.append(this.b);
        sb.append(", definition=");
        sb.append(this.c);
        sb.append(", image=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }
}
