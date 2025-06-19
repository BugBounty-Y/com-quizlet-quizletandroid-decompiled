package com.quizlet.explanations.textbook.data;

import androidx.compose.animation.d0;
import com.quizlet.data.model.X;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a extends c {
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final boolean f;
    public final boolean g;
    public final X h;

    public a(String title, String edition, String authors, String isbn, String imageUrl, boolean z, boolean z2, X x) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(edition, "edition");
        Intrinsics.checkNotNullParameter(authors, "authors");
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        this.a = title;
        this.b = edition;
        this.c = authors;
        this.d = isbn;
        this.e = imageUrl;
        this.f = z;
        this.g = z2;
        this.h = x;
    }

    @Override // com.quizlet.explanations.textbook.data.c
    public final String a() {
        return this.c;
    }

    @Override // com.quizlet.explanations.textbook.data.c
    public final String b() {
        return this.b;
    }

    @Override // com.quizlet.explanations.textbook.data.c
    public final String c() {
        return this.e;
    }

    @Override // com.quizlet.explanations.textbook.data.c
    public final String d() {
        return this.d;
    }

    @Override // com.quizlet.explanations.textbook.data.c
    public final String e() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c) && Intrinsics.b(this.d, aVar.d) && Intrinsics.b(this.e, aVar.e) && this.f == aVar.f && this.g == aVar.g && Intrinsics.b(this.h, aVar.h);
    }

    public final int hashCode() {
        int iG = d0.g(d0.g(d0.e(d0.e(d0.e(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g);
        X x = this.h;
        return iG + (x == null ? 0 : x.hashCode());
    }

    public final String toString() {
        return "LoggedIn(title=" + this.a + ", edition=" + this.b + ", authors=" + this.c + ", isbn=" + this.d + ", imageUrl=" + this.e + ", isPremium=" + this.f + ", isPlusEnabled=" + this.g + ", meteringInfo=" + this.h + ")";
    }
}
