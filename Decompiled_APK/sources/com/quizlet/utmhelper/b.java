package com.quizlet.utmhelper;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final String a;
    public final String b;

    public b(String str, String utmBlob) {
        Intrinsics.checkNotNullParameter(utmBlob, "utmBlob");
        this.a = str;
        this.b = utmBlob;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b);
    }

    public final int hashCode() {
        String str = this.a;
        return this.b.hashCode() + ((str == null ? 0 : str.hashCode()) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("EncodedUtmParams(userId=");
        sb.append(this.a);
        sb.append(", utmBlob=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
