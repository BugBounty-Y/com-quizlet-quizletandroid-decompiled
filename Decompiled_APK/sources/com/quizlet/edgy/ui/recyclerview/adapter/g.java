package com.quizlet.edgy.ui.recyclerview.adapter;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class g implements com.quizlet.baserecyclerview.a {
    public final long a;
    public final String b;
    public final String c;
    public final String d;
    public final int e;
    public final long f;
    public final long g;

    public g(int i, long j, long j2, String name, String str, String str2) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = j;
        this.b = name;
        this.c = str;
        this.d = str2;
        this.e = i;
        this.f = j2;
        this.g = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return this.a == gVar.a && Intrinsics.b(this.b, gVar.b) && Intrinsics.b(this.c, gVar.c) && Intrinsics.b(this.d, gVar.d) && this.e == gVar.e && this.f == gVar.f;
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return Long.valueOf(this.g);
    }

    public final int hashCode() {
        int iE = d0.e(Long.hashCode(this.a) * 31, 31, this.b);
        String str = this.c;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.d;
        return Long.hashCode(this.f) + d0.b(this.e, (iHashCode + (str2 != null ? str2.hashCode() : 0)) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SearchCourseItem(id=");
        sb.append(this.a);
        sb.append(", name=");
        sb.append(this.b);
        sb.append(", code=");
        sb.append(this.c);
        sb.append(", countryCode=");
        sb.append(this.d);
        sb.append(", lastModified=");
        sb.append(this.e);
        sb.append(", timestamp=");
        return android.support.v4.media.session.a.g(this.f, ")", sb);
    }
}
