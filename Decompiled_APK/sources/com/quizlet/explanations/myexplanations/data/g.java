package com.quizlet.explanations.myexplanations.data;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class g implements com.quizlet.baserecyclerview.a, a {
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final long g;
    public final String h;
    public final String i;
    public final String j;
    public final boolean k;
    public final boolean l;
    public final long m;
    public final String n;

    public g(String id, String exercise, String chapterName, String str, String str2, String str3, long j, String textbookIsbn, String textbookTitle, String textbookImageUrl, boolean z, boolean z2, long j2) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(exercise, "exercise");
        Intrinsics.checkNotNullParameter(chapterName, "chapterName");
        Intrinsics.checkNotNullParameter(textbookIsbn, "textbookIsbn");
        Intrinsics.checkNotNullParameter(textbookTitle, "textbookTitle");
        Intrinsics.checkNotNullParameter(textbookImageUrl, "textbookImageUrl");
        this.a = id;
        this.b = exercise;
        this.c = chapterName;
        this.d = str;
        this.e = str2;
        this.f = str3;
        this.g = j;
        this.h = textbookIsbn;
        this.i = textbookTitle;
        this.j = textbookImageUrl;
        this.k = z;
        this.l = z2;
        this.m = j2;
        this.n = AbstractC0147y.d("exercise-", id);
    }

    @Override // com.quizlet.explanations.myexplanations.data.a
    public final long a() {
        return this.m;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Intrinsics.b(this.a, gVar.a) && Intrinsics.b(this.b, gVar.b) && Intrinsics.b(this.c, gVar.c) && Intrinsics.b(this.d, gVar.d) && Intrinsics.b(this.e, gVar.e) && Intrinsics.b(this.f, gVar.f) && this.g == gVar.g && Intrinsics.b(this.h, gVar.h) && Intrinsics.b(this.i, gVar.i) && Intrinsics.b(this.j, gVar.j) && this.k == gVar.k && this.l == gVar.l && this.m == gVar.m;
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return this.n;
    }

    public final int hashCode() {
        int iE = d0.e(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c);
        String str = this.d;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.e;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.f;
        return Long.hashCode(this.m) + d0.g(d0.g(d0.e(d0.e(d0.e(d0.d((iHashCode2 + (str3 != null ? str3.hashCode() : 0)) * 31, 31, this.g), 31, this.h), 31, this.i), 31, this.j), 31, this.k), 31, this.l);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MyExplanationsExerciseItem(id=");
        sb.append(this.a);
        sb.append(", exercise=");
        sb.append(this.b);
        sb.append(", chapterName=");
        sb.append(this.c);
        sb.append(", sectionName=");
        sb.append(this.d);
        sb.append(", groupName=");
        sb.append(this.e);
        sb.append(", pageNumber=");
        sb.append(this.f);
        sb.append(", textbookId=");
        sb.append(this.g);
        sb.append(", textbookIsbn=");
        sb.append(this.h);
        sb.append(", textbookTitle=");
        sb.append(this.i);
        sb.append(", textbookImageUrl=");
        sb.append(this.j);
        sb.append(", textbookIsPremium=");
        sb.append(this.k);
        sb.append(", isPlusEnabled=");
        sb.append(this.l);
        sb.append(", timestampSec=");
        return android.support.v4.media.session.a.g(this.m, ")", sb);
    }
}
