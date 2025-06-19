package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.o1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4154o1 implements Z {
    public final long a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final long f;
    public final String g;
    public final List h;

    public C4154o1(long j, String prompt, String str, String slug, List subjects, long j2, String webUrl, String str2) {
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(slug, "slug");
        Intrinsics.checkNotNullParameter(webUrl, "webUrl");
        Intrinsics.checkNotNullParameter(subjects, "subjects");
        this.a = j;
        this.b = prompt;
        this.c = str;
        this.d = slug;
        this.e = webUrl;
        this.f = j2;
        this.g = str2;
        this.h = subjects;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4154o1)) {
            return false;
        }
        C4154o1 c4154o1 = (C4154o1) obj;
        return this.a == c4154o1.a && Intrinsics.b(this.b, c4154o1.b) && Intrinsics.b(this.c, c4154o1.c) && Intrinsics.b(this.d, c4154o1.d) && Intrinsics.b(this.e, c4154o1.e) && this.f == c4154o1.f && Intrinsics.b(this.g, c4154o1.g) && Intrinsics.b(this.h, c4154o1.h);
    }

    public final int hashCode() {
        int iE = androidx.compose.animation.d0.e(Long.hashCode(this.a) * 31, 31, this.b);
        String str = this.c;
        int iD = androidx.compose.animation.d0.d(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e((iE + (str == null ? 0 : str.hashCode())) * 31, 31, this.d), 31, this.e), 31, this.f);
        String str2 = this.g;
        return this.h.hashCode() + ((iD + (str2 != null ? str2.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("QuestionSearchResult(id=");
        sb.append(this.a);
        sb.append(", prompt=");
        sb.append(this.b);
        sb.append(", clarification=");
        sb.append(this.c);
        sb.append(", slug=");
        sb.append(this.d);
        sb.append(", webUrl=");
        sb.append(this.e);
        sb.append(", createdTimestamp=");
        sb.append(this.f);
        sb.append(", humanized=");
        sb.append(this.g);
        sb.append(", subjects=");
        return android.support.v4.media.session.a.n(")", sb, this.h);
    }
}
