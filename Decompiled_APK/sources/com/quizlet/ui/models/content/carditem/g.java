package com.quizlet.ui.models.content.carditem;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.K0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements com.quizlet.ui.models.search.a, com.quizlet.ui.models.impressions.a {
    public final long a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final int f;
    public final String g;
    public final boolean h;
    public final boolean i;
    public final K0 j;

    public g(int i, long j, String isbn, String title, String edition, String authors, String str, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(edition, "edition");
        Intrinsics.checkNotNullParameter(authors, "authors");
        this.a = j;
        this.b = isbn;
        this.c = title;
        this.d = edition;
        this.e = authors;
        this.f = i;
        this.g = str;
        this.h = z;
        this.i = z2;
        this.j = K0.FREE;
    }

    @Override // com.quizlet.ui.models.impressions.a
    public final K0 a() {
        return this.j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return this.a == gVar.a && Intrinsics.b(this.b, gVar.b) && Intrinsics.b(this.c, gVar.c) && Intrinsics.b(this.d, gVar.d) && Intrinsics.b(this.e, gVar.e) && this.f == gVar.f && Intrinsics.b(this.g, gVar.g) && this.h == gVar.h && this.i == gVar.i;
    }

    @Override // com.quizlet.ui.models.impressions.a
    public final long getItemId() {
        return this.a;
    }

    @Override // com.quizlet.ui.models.search.a
    public final Object getKey() {
        return this.b;
    }

    @Override // com.quizlet.ui.models.impressions.a
    public final int getModelType() {
        return 14;
    }

    public final int hashCode() {
        int iB = d0.b(this.f, d0.e(d0.e(d0.e(d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31);
        String str = this.g;
        return Boolean.hashCode(this.i) + d0.g((iB + (str == null ? 0 : str.hashCode())) * 31, 31, this.h);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TextbookCardUiModel(id=");
        sb.append(this.a);
        sb.append(", isbn=");
        sb.append(this.b);
        sb.append(", title=");
        sb.append(this.c);
        sb.append(", edition=");
        sb.append(this.d);
        sb.append(", authors=");
        sb.append(this.e);
        sb.append(", solutionsCount=");
        sb.append(this.f);
        sb.append(", image=");
        sb.append(this.g);
        sb.append(", isPremium=");
        sb.append(this.h);
        sb.append(", isPlusEnabled=");
        return android.support.v4.media.session.a.o(")", sb, this.i);
    }
}
