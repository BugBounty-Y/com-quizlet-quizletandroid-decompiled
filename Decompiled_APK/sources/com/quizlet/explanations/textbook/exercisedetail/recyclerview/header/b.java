package com.quizlet.explanations.textbook.exercisedetail.recyclerview.header;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.c7;
import com.quizlet.data.model.X;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b extends d {
    public final String d;
    public final String e;
    public final String f;
    public final String g;
    public final String h;
    public final boolean i;
    public final boolean j;
    public final X k;
    public final boolean l;

    public b(String name, String subHeaderChapterTitle, String str, String str2, String str3, boolean z, boolean z2, X x, boolean z3) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(subHeaderChapterTitle, "subHeaderChapterTitle");
        this.d = name;
        this.e = subHeaderChapterTitle;
        this.f = str;
        this.g = str2;
        this.h = str3;
        this.i = z;
        this.j = z2;
        this.k = x;
        this.l = z3;
        if (!((Boolean) this.a.getValue()).booleanValue() || x == null) {
            return;
        }
        c7.c(x);
    }

    @Override // com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.d
    public final X a() {
        return this.k;
    }

    @Override // com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.d
    public final String b() {
        return this.d;
    }

    @Override // com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.d
    public final String c() {
        return this.h;
    }

    @Override // com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.d
    public final String d() {
        return this.e;
    }

    @Override // com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.d
    public final String e() {
        return this.f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.d, bVar.d) && Intrinsics.b(this.e, bVar.e) && Intrinsics.b(this.f, bVar.f) && Intrinsics.b(this.g, bVar.g) && Intrinsics.b(this.h, bVar.h) && this.i == bVar.i && this.j == bVar.j && Intrinsics.b(this.k, bVar.k) && this.l == bVar.l;
    }

    @Override // com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.d
    public final boolean f() {
        return this.l;
    }

    @Override // com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.d
    public final boolean g() {
        return this.j;
    }

    @Override // com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.d
    public final boolean h() {
        return this.i;
    }

    public final int hashCode() {
        int iE = d0.e(this.d.hashCode() * 31, 31, this.e);
        String str = this.f;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.g;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.h;
        int iG = d0.g(d0.g((iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31, 31, this.i), 31, this.j);
        X x = this.k;
        return Boolean.hashCode(this.l) + ((iG + (x != null ? x.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LoggedIn(name=");
        sb.append(this.d);
        sb.append(", subHeaderChapterTitle=");
        sb.append(this.e);
        sb.append(", subHeaderSectionTitle=");
        sb.append(this.f);
        sb.append(", subHeaderGroupTitle=");
        sb.append(this.g);
        sb.append(", pageNumber=");
        sb.append(this.h);
        sb.append(", isPremium=");
        sb.append(this.i);
        sb.append(", isPlusEnabled=");
        sb.append(this.j);
        sb.append(", meteringInfo=");
        sb.append(this.k);
        sb.append(", isContentLimited=");
        return android.support.v4.media.session.a.o(")", sb, this.l);
    }
}
