package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_document_scanner.E6;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class E0 extends E6 implements B0 {
    public final long a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final long g;
    public final String h;
    public final long i;
    public final String j;
    public final String k;
    public final String l;
    public final boolean m;
    public final String n;

    public E0(long j, String mediaExerciseId, String exercise, String chapterName, String str, String str2, long j2, String str3, long j3, String textbookIsbn, String textbookTitle, String textbookImageUrl, boolean z) {
        Intrinsics.checkNotNullParameter(mediaExerciseId, "mediaExerciseId");
        Intrinsics.checkNotNullParameter(exercise, "exercise");
        Intrinsics.checkNotNullParameter(chapterName, "chapterName");
        Intrinsics.checkNotNullParameter(textbookIsbn, "textbookIsbn");
        Intrinsics.checkNotNullParameter(textbookTitle, "textbookTitle");
        Intrinsics.checkNotNullParameter(textbookImageUrl, "textbookImageUrl");
        this.a = j;
        this.b = mediaExerciseId;
        this.c = exercise;
        this.d = chapterName;
        this.e = str;
        this.f = str2;
        this.g = j2;
        this.h = str3;
        this.i = j3;
        this.j = textbookIsbn;
        this.k = textbookTitle;
        this.l = textbookImageUrl;
        this.m = z;
        this.n = mediaExerciseId;
    }

    @Override // com.quizlet.data.model.B0
    public final long a() {
        return this.g;
    }

    @Override // com.quizlet.data.model.B0
    public final int b() {
        return 15;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof E0)) {
            return false;
        }
        E0 e0 = (E0) obj;
        return this.a == e0.a && Intrinsics.b(this.b, e0.b) && Intrinsics.b(this.c, e0.c) && Intrinsics.b(this.d, e0.d) && Intrinsics.b(this.e, e0.e) && Intrinsics.b(this.f, e0.f) && this.g == e0.g && Intrinsics.b(this.h, e0.h) && this.i == e0.i && Intrinsics.b(this.j, e0.j) && Intrinsics.b(this.k, e0.k) && Intrinsics.b(this.l, e0.l) && this.m == e0.m;
    }

    @Override // com.quizlet.data.model.B0
    public final String getItemId() {
        return this.n;
    }

    public final int hashCode() {
        int iE = androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d);
        String str = this.e;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.f;
        int iD = androidx.compose.animation.d0.d((iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31, 31, this.g);
        String str3 = this.h;
        return Boolean.hashCode(this.m) + androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.d((iD + (str3 != null ? str3.hashCode() : 0)) * 31, 31, this.i), 31, this.j), 31, this.k), 31, this.l);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MyExplanationsTextbookExercise(id=");
        sb.append(this.a);
        sb.append(", mediaExerciseId=");
        sb.append(this.b);
        sb.append(", exercise=");
        sb.append(this.c);
        sb.append(", chapterName=");
        sb.append(this.d);
        sb.append(", sectionName=");
        sb.append(this.e);
        sb.append(", groupName=");
        sb.append(this.f);
        sb.append(", timestampSec=");
        sb.append(this.g);
        sb.append(", pageNumber=");
        sb.append(this.h);
        sb.append(", textbookId=");
        sb.append(this.i);
        sb.append(", textbookIsbn=");
        sb.append(this.j);
        sb.append(", textbookTitle=");
        sb.append(this.k);
        sb.append(", textbookImageUrl=");
        sb.append(this.l);
        sb.append(", textbookIsPremium=");
        return android.support.v4.media.session.a.o(")", sb, this.m);
    }
}
