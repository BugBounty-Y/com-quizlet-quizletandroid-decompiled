package com.quizlet.explanations.myexplanations.data;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class q implements com.quizlet.baserecyclerview.a {
    public final long a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final boolean g;
    public final boolean h;
    public final int i;
    public final String j;

    public q(int i, long j, String isbn, String title, String imageUrl, String edition, String authors, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        Intrinsics.checkNotNullParameter(edition, "edition");
        Intrinsics.checkNotNullParameter(authors, "authors");
        this.a = j;
        this.b = isbn;
        this.c = title;
        this.d = imageUrl;
        this.e = edition;
        this.f = authors;
        this.g = z;
        this.h = z2;
        this.i = i;
        this.j = AbstractC0147y.d("textbook-", isbn);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof q)) {
            return false;
        }
        q qVar = (q) obj;
        return this.a == qVar.a && Intrinsics.b(this.b, qVar.b) && Intrinsics.b(this.c, qVar.c) && Intrinsics.b(this.d, qVar.d) && Intrinsics.b(this.e, qVar.e) && Intrinsics.b(this.f, qVar.f) && this.g == qVar.g && this.h == qVar.h && this.i == qVar.i;
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return this.j;
    }

    public final int hashCode() {
        return Integer.hashCode(this.i) + d0.g(d0.g(d0.e(d0.e(d0.e(d0.e(d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g), 31, this.h);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MyExplanationsTextbookItem(id=");
        sb.append(this.a);
        sb.append(", isbn=");
        sb.append(this.b);
        sb.append(", title=");
        sb.append(this.c);
        sb.append(", imageUrl=");
        sb.append(this.d);
        sb.append(", edition=");
        sb.append(this.e);
        sb.append(", authors=");
        sb.append(this.f);
        sb.append(", isPremium=");
        sb.append(this.g);
        sb.append(", isPlusEnabled=");
        sb.append(this.h);
        sb.append(", verifiedSolutionCount=");
        return android.support.v4.media.session.a.r(sb, this.i, ")");
    }
}
