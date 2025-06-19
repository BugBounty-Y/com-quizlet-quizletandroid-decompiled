package com.quizlet.quizletandroid.ui.group.classcontent.models;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends a {
    public final long a;
    public final b b;
    public final boolean c;
    public final long d;
    public final String e;
    public final int f;
    public final boolean g;
    public final boolean h;
    public final boolean i;
    public final String j;

    public d(long j, b bVar, boolean z, long j2, String name, int i, boolean z2, boolean z3, boolean z4, String str) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = j;
        this.b = bVar;
        this.c = z;
        this.d = j2;
        this.e = name;
        this.f = i;
        this.g = z2;
        this.h = z3;
        this.i = z4;
        this.j = str;
    }

    @Override // com.quizlet.quizletandroid.ui.group.classcontent.models.a
    public final long a() {
        return this.d;
    }

    @Override // com.quizlet.quizletandroid.ui.group.classcontent.models.a
    public final long b() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && Intrinsics.b(this.b, dVar.b) && this.c == dVar.c && this.d == dVar.d && Intrinsics.b(this.e, dVar.e) && this.f == dVar.f && this.g == dVar.g && this.h == dVar.h && this.i == dVar.i && Intrinsics.b(this.j, dVar.j);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        b bVar = this.b;
        int iG = d0.g(d0.g(d0.g(d0.b(this.f, d0.e(d0.d(d0.g((iHashCode + (bVar == null ? 0 : bVar.hashCode())) * 31, 31, this.c), 31, this.d), 31, this.e), 31), 31, this.g), 31, this.h), 31, this.i);
        String str = this.j;
        return iG + (str != null ? str.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudySetClassContentItem(id=");
        sb.append(this.a);
        sb.append(", classContentUser=");
        sb.append(this.b);
        sb.append(", canEdit=");
        sb.append(this.c);
        sb.append(", addedTimestampSec=");
        sb.append(this.d);
        sb.append(", name=");
        sb.append(this.e);
        sb.append(", numStudiableCards=");
        sb.append(this.f);
        sb.append(", hasImages=");
        sb.append(this.g);
        sb.append(", hasDiagrams=");
        sb.append(this.h);
        sb.append(", hasPassword=");
        sb.append(this.i);
        sb.append(", thumbnailUrl=");
        return android.support.v4.media.session.a.t(sb, this.j, ")");
    }
}
