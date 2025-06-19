package com.quizlet.quizletandroid.managers.audio;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final String a;
    public final long b;
    public final String c;
    public final int d;

    public c(int i, long j, String str, String str2) {
        this.a = str;
        this.b = j;
        this.c = str2;
        this.d = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && this.b == cVar.b && Intrinsics.b(this.c, cVar.c) && this.d == cVar.d;
    }

    public final int hashCode() {
        String str = this.a;
        int iD = d0.d((str == null ? 0 : str.hashCode()) * 31, 31, this.b);
        String str2 = this.c;
        return Integer.hashCode(this.d) + ((iD + (str2 != null ? str2.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Payload(text=");
        sb.append(this.a);
        sb.append(", id=");
        sb.append(this.b);
        sb.append(", language=");
        sb.append(this.c);
        sb.append(", languageDescriptionFallbackRes=");
        return android.support.v4.media.session.a.r(sb, this.d, ")");
    }
}
