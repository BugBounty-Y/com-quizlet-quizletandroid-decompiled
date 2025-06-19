package com.quizlet.utmhelper;

import com.quizlet.utm.a;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final Long a;
    public final String b;
    public final String c;
    public final String d;

    public a(Long l, String str, String str2, String str3) {
        this.a = l;
        this.b = str;
        this.c = str2;
        this.d = str3;
    }

    public final a.C0023a a() {
        return new a.C0023a(new a.c(com.quizlet.utm.campaigns.b.Companion.fromValue(this.b), com.quizlet.utm.mediums.b.Companion.fromValue(this.c), com.quizlet.utm.sources.b.Companion.fromValue(this.d)), this.a);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c) && Intrinsics.b(this.d, aVar.d);
    }

    public final int hashCode() {
        Long l = this.a;
        int iHashCode = (l == null ? 0 : l.hashCode()) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.c;
        int iHashCode3 = (iHashCode2 + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.d;
        return iHashCode3 + (str3 != null ? str3.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("DecodedUtmParams(userId=");
        sb.append(this.a);
        sb.append(", campaign=");
        sb.append(this.b);
        sb.append(", medium=");
        sb.append(this.c);
        sb.append(", source=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }
}
