package com.quizlet.features.match.highscore;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements Comparable {
    public final String a;
    public final long b;
    public final String c;
    public final int d;
    public final long e;
    public final long f;
    public final boolean g;

    public a(String str, long j, String str2, int i, long j2, long j3, boolean z) {
        this.a = str;
        this.b = j;
        this.c = str2;
        this.d = i;
        this.e = j2;
        this.f = j3;
        this.g = z;
    }

    public static a a(a aVar, int i) {
        return new a(aVar.a, aVar.b, aVar.c, i, aVar.e, aVar.f, aVar.g);
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        a other = (a) obj;
        Intrinsics.checkNotNullParameter(other, "other");
        int iH = Intrinsics.h(this.b, other.b);
        return iH == 0 ? Intrinsics.h(this.f, other.f) : iH;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && this.b == aVar.b && Intrinsics.b(this.c, aVar.c) && this.d == aVar.d && this.e == aVar.e && this.f == aVar.f && this.g == aVar.g;
    }

    public final int hashCode() {
        String str = this.a;
        int iD = d0.d((str == null ? 0 : str.hashCode()) * 31, 31, this.b);
        String str2 = this.c;
        return Boolean.hashCode(this.g) + d0.d(d0.d(d0.b(this.d, (iD + (str2 != null ? str2.hashCode() : 0)) * 31, 31), 31, this.e), 31, this.f);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("HighScoreInfo(username=");
        sb.append(this.a);
        sb.append(", scoreSec=");
        sb.append(this.b);
        sb.append(", profileImg=");
        sb.append(this.c);
        sb.append(", rank=");
        sb.append(this.d);
        sb.append(", userId=");
        sb.append(this.e);
        sb.append(", timestampMs=");
        sb.append(this.f);
        sb.append(", usersScore=");
        return android.support.v4.media.session.a.o(")", sb, this.g);
    }
}
