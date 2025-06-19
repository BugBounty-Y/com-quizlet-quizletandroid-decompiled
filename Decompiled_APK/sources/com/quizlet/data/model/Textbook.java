package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_document_scanner.G6;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class Textbook extends G6 implements Z {
    public final long a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final boolean f;
    public final int g;
    public final String h;
    public final String i;
    public final boolean j;
    public final String k;
    public final List l;

    public Textbook(long j, String isbn, String title, String imageUrl, String edition, boolean z, int i, String authors, String imageThumbnailUrl, boolean z2, String webUrl, List tableOfContents) {
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        Intrinsics.checkNotNullParameter(edition, "edition");
        Intrinsics.checkNotNullParameter(authors, "authors");
        Intrinsics.checkNotNullParameter(imageThumbnailUrl, "imageThumbnailUrl");
        Intrinsics.checkNotNullParameter(webUrl, "webUrl");
        Intrinsics.checkNotNullParameter(tableOfContents, "tableOfContents");
        this.a = j;
        this.b = isbn;
        this.c = title;
        this.d = imageUrl;
        this.e = edition;
        this.f = z;
        this.g = i;
        this.h = authors;
        this.i = imageThumbnailUrl;
        this.j = z2;
        this.k = webUrl;
        this.l = tableOfContents;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Textbook)) {
            return false;
        }
        Textbook textbook = (Textbook) obj;
        if (this.a != textbook.a || !Intrinsics.b(this.b, textbook.b) || !Intrinsics.b(this.c, textbook.c) || !Intrinsics.b(this.d, textbook.d) || !Intrinsics.b(this.e, textbook.e) || this.f != textbook.f || this.g != textbook.g || !Intrinsics.b(this.h, textbook.h) || !Intrinsics.b(this.i, textbook.i) || this.j != textbook.j || !Intrinsics.b(this.k, textbook.k)) {
            return false;
        }
        kotlin.collections.K k = TableOfContents.b;
        return Intrinsics.b(this.l, textbook.l);
    }

    public final int hashCode() {
        int iE = androidx.compose.animation.d0.e(androidx.compose.animation.d0.g(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.b(this.g, androidx.compose.animation.d0.g(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31), 31, this.h), 31, this.i), 31, this.j), 31, this.k);
        kotlin.collections.K k = TableOfContents.b;
        return this.l.hashCode() + iE;
    }

    public final String toString() {
        List list = this.l;
        kotlin.collections.K k = TableOfContents.b;
        String str = "TableOfContents(items=" + list + ")";
        StringBuilder sb = new StringBuilder("Textbook(id=");
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
        sb.append(", verifiedSolutionCount=");
        sb.append(this.g);
        sb.append(", authors=");
        sb.append(this.h);
        sb.append(", imageThumbnailUrl=");
        sb.append(this.i);
        sb.append(", hasSolutions=");
        sb.append(this.j);
        sb.append(", webUrl=");
        return androidx.compose.ui.node.B.j(sb, this.k, ", tableOfContents=", str, ")");
    }
}
