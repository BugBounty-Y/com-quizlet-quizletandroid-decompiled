package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_document_scanner.G6;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class D0 extends G6 implements B0 {
    public final long a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final boolean f;
    public final long g;
    public final int h;
    public final String i;
    public final String j;

    public D0(long j, String isbn, String title, String imageUrl, String edition, boolean z, long j2, int i, String authors) {
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
        this.f = z;
        this.g = j2;
        this.h = i;
        this.i = authors;
        this.j = isbn;
    }

    @Override // com.quizlet.data.model.B0
    public final long a() {
        return this.g;
    }

    @Override // com.quizlet.data.model.B0
    public final int b() {
        return 14;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof D0)) {
            return false;
        }
        D0 d0 = (D0) obj;
        return this.a == d0.a && Intrinsics.b(this.b, d0.b) && Intrinsics.b(this.c, d0.c) && Intrinsics.b(this.d, d0.d) && Intrinsics.b(this.e, d0.e) && this.f == d0.f && this.g == d0.g && this.h == d0.h && Intrinsics.b(this.i, d0.i);
    }

    @Override // com.quizlet.data.model.B0
    public final String getItemId() {
        return this.j;
    }

    public final int hashCode() {
        return this.i.hashCode() + androidx.compose.animation.d0.b(this.h, androidx.compose.animation.d0.d(androidx.compose.animation.d0.g(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MyExplanationsTextbook(id=");
        sb.append(this.a);
        sb.append(", isbn=");
        sb.append(this.b);
        sb.append(", title=");
        sb.append(this.c);
        sb.append(", imageUrl=");
        sb.append(this.d);
        sb.append(", edition=");
        sb.append(this.e);
        sb.append(", isPremium=");
        sb.append(this.f);
        sb.append(", timestampSec=");
        sb.append(this.g);
        sb.append(", verifiedSolutionCount=");
        sb.append(this.h);
        sb.append(", authors=");
        return android.support.v4.media.session.a.t(sb, this.i, ")");
    }
}
