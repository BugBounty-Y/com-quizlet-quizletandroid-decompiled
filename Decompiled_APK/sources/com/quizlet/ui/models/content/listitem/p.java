package com.quizlet.ui.models.content.listitem;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p {
    public final String a;
    public final String b;
    public final String c;
    public final String d;

    public p(String isbn, String title, String edition, String authors) {
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(edition, "edition");
        Intrinsics.checkNotNullParameter(authors, "authors");
        this.a = isbn;
        this.b = title;
        this.c = edition;
        this.d = authors;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof p)) {
            return false;
        }
        p pVar = (p) obj;
        return Intrinsics.b(this.a, pVar.a) && Intrinsics.b(this.b, pVar.b) && Intrinsics.b(this.c, pVar.c) && Intrinsics.b(this.d, pVar.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.e(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TextbookContentMetadata(isbn=");
        sb.append(this.a);
        sb.append(", title=");
        sb.append(this.b);
        sb.append(", edition=");
        sb.append(this.c);
        sb.append(", authors=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }
}
