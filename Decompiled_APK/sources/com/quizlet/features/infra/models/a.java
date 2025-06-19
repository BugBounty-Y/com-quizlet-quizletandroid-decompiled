package com.quizlet.features.infra.models;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final String a;
    public final String b;
    public final boolean c;
    public final String d;

    public a(String str, String str2, String str3, boolean z) {
        this.a = str;
        this.b = str2;
        this.c = z;
        this.d = str3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && this.c == aVar.c && Intrinsics.b(this.d, aVar.d);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.b;
        int iG = d0.g((iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31, 31, this.c);
        String str3 = this.d;
        return iG + (str3 != null ? str3.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ContentTextData(text=");
        sb.append(this.a);
        sb.append(", languageCode=");
        sb.append(this.b);
        sb.append(", shouldShowPlaceholder=");
        sb.append(this.c);
        sb.append(", richText=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }
}
