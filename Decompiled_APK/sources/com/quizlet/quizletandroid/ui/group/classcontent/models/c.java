package com.quizlet.quizletandroid.ui.group.classcontent.models;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends a {
    public final long a;
    public final b b;
    public final boolean c;
    public final long d;
    public final String e;
    public final int f;

    public c(long j, b bVar, boolean z, long j2, String name, int i) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = j;
        this.b = bVar;
        this.c = z;
        this.d = j2;
        this.e = name;
        this.f = i;
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
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && Intrinsics.b(this.b, cVar.b) && this.c == cVar.c && this.d == cVar.d && Intrinsics.b(this.e, cVar.e) && this.f == cVar.f;
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        b bVar = this.b;
        return Integer.hashCode(this.f) + d0.e(d0.d(d0.g((iHashCode + (bVar == null ? 0 : bVar.hashCode())) * 31, 31, this.c), 31, this.d), 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FolderClassContentItem(id=");
        sb.append(this.a);
        sb.append(", classContentUser=");
        sb.append(this.b);
        sb.append(", canEdit=");
        sb.append(this.c);
        sb.append(", addedTimestampSec=");
        sb.append(this.d);
        sb.append(", name=");
        sb.append(this.e);
        sb.append(", numStudySets=");
        return android.support.v4.media.session.a.r(sb, this.f, ")");
    }
}
