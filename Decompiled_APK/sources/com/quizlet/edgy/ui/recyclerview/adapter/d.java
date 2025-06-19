package com.quizlet.edgy.ui.recyclerview.adapter;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d implements com.quizlet.baserecyclerview.a {
    public final long a;
    public final String b;
    public final String c;
    public final long d;

    public d(long j, String str, String str2) {
        this.a = j;
        this.b = str;
        this.c = str2;
        this.d = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && Intrinsics.b(this.b, dVar.b) && Intrinsics.b(this.c, dVar.c);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return Long.valueOf(this.d);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.c;
        return iHashCode2 + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CourseSelectedItem(id=");
        sb.append(this.a);
        sb.append(", code=");
        sb.append(this.b);
        sb.append(", name=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
