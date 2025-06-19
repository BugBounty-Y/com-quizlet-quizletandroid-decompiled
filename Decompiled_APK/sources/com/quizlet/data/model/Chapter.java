package com.quizlet.data.model;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class Chapter extends TableOfContentItem implements InterfaceC4138j0, InterfaceC4141k0 {
    public final long a;
    public final boolean b;
    public final String c;
    public final String d;
    public final List e;
    public final List f;

    public Chapter(long j, String str, String str2, boolean z, List children, List exercises) {
        Intrinsics.checkNotNullParameter(children, "children");
        Intrinsics.checkNotNullParameter(exercises, "exercises");
        this.a = j;
        this.b = z;
        this.c = str;
        this.d = str2;
        this.e = children;
        this.f = exercises;
    }

    @Override // com.quizlet.data.model.InterfaceC4141k0
    public final List a() {
        return this.f;
    }

    @Override // com.quizlet.data.model.TableOfContentItem
    public final long b() {
        return this.a;
    }

    @Override // com.quizlet.data.model.InterfaceC4138j0
    public final List d() {
        return this.e;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Chapter)) {
            return false;
        }
        Chapter chapter = (Chapter) obj;
        return this.a == chapter.a && this.b == chapter.b && Intrinsics.b(this.c, chapter.c) && Intrinsics.b(this.d, chapter.d) && Intrinsics.b(this.e, chapter.e) && Intrinsics.b(this.f, chapter.f);
    }

    public final int hashCode() {
        int iG = androidx.compose.animation.d0.g(Long.hashCode(this.a) * 31, 31, this.b);
        String str = this.c;
        int iHashCode = (iG + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.d;
        return this.f.hashCode() + androidx.compose.animation.d0.f((iHashCode + (str2 != null ? str2.hashCode() : 0)) * 31, 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Chapter(id=");
        sb.append(this.a);
        sb.append(", hasSolutions=");
        sb.append(this.b);
        sb.append(", title=");
        sb.append(this.c);
        sb.append(", name=");
        sb.append(this.d);
        sb.append(", children=");
        sb.append(this.e);
        sb.append(", exercises=");
        return android.support.v4.media.session.a.n(")", sb, this.f);
    }
}
