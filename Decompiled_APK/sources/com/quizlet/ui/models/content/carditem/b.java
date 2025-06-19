package com.quizlet.ui.models.content.carditem;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final String g;
    public final boolean h;

    public b(String mediaExerciseId, String exercise, String textbookTitle, String str, String chapterName, String str2, String str3, boolean z) {
        Intrinsics.checkNotNullParameter(mediaExerciseId, "mediaExerciseId");
        Intrinsics.checkNotNullParameter(exercise, "exercise");
        Intrinsics.checkNotNullParameter(textbookTitle, "textbookTitle");
        Intrinsics.checkNotNullParameter(chapterName, "chapterName");
        this.a = mediaExerciseId;
        this.b = exercise;
        this.c = textbookTitle;
        this.d = str;
        this.e = chapterName;
        this.f = str2;
        this.g = str3;
        this.h = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b) && Intrinsics.b(this.c, bVar.c) && Intrinsics.b(this.d, bVar.d) && Intrinsics.b(this.e, bVar.e) && Intrinsics.b(this.f, bVar.f) && Intrinsics.b(this.g, bVar.g) && this.h == bVar.h;
    }

    public final int hashCode() {
        int iE = d0.e(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c);
        String str = this.d;
        int iE2 = d0.e((iE + (str == null ? 0 : str.hashCode())) * 31, 31, this.e);
        String str2 = this.f;
        int iHashCode = (iE2 + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.g;
        return Boolean.hashCode(this.h) + ((iHashCode + (str3 != null ? str3.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExerciseCardUiModel(mediaExerciseId=");
        sb.append(this.a);
        sb.append(", exercise=");
        sb.append(this.b);
        sb.append(", textbookTitle=");
        sb.append(this.c);
        sb.append(", textbookImageUrl=");
        sb.append(this.d);
        sb.append(", chapterName=");
        sb.append(this.e);
        sb.append(", sectionName=");
        sb.append(this.f);
        sb.append(", pageNumber=");
        sb.append(this.g);
        sb.append(", isPlusEnabled=");
        return android.support.v4.media.session.a.o(")", sb, this.h);
    }
}
