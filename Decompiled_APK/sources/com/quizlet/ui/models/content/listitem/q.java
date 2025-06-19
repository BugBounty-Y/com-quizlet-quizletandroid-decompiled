package com.quizlet.ui.models.content.listitem;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class q {
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final String g;
    public final String h;
    public final p i;

    public q(String mediaExerciseId, String exercise, String chapter, String str, String str2, String str3, String str4, String str5, p textbookMetadata) {
        Intrinsics.checkNotNullParameter(mediaExerciseId, "mediaExerciseId");
        Intrinsics.checkNotNullParameter(exercise, "exercise");
        Intrinsics.checkNotNullParameter(chapter, "chapter");
        Intrinsics.checkNotNullParameter(textbookMetadata, "textbookMetadata");
        this.a = mediaExerciseId;
        this.b = exercise;
        this.c = chapter;
        this.d = str;
        this.e = str2;
        this.f = str3;
        this.g = str4;
        this.h = str5;
        this.i = textbookMetadata;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof q)) {
            return false;
        }
        q qVar = (q) obj;
        return Intrinsics.b(this.a, qVar.a) && Intrinsics.b(this.b, qVar.b) && Intrinsics.b(this.c, qVar.c) && Intrinsics.b(this.d, qVar.d) && Intrinsics.b(this.e, qVar.e) && Intrinsics.b(this.f, qVar.f) && Intrinsics.b(this.g, qVar.g) && Intrinsics.b(this.h, qVar.h) && Intrinsics.b(this.i, qVar.i);
    }

    public final int hashCode() {
        int iE = d0.e(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c);
        String str = this.d;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.e;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.f;
        int iHashCode3 = (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.g;
        int iHashCode4 = (iHashCode3 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.h;
        return this.i.hashCode() + ((iHashCode4 + (str5 != null ? str5.hashCode() : 0)) * 31);
    }

    public final String toString() {
        return "TextbookExerciseContentMetadata(mediaExerciseId=" + this.a + ", exercise=" + this.b + ", chapter=" + this.c + ", chapterTitle=" + this.d + ", section=" + this.e + ", sectionTitle=" + this.f + ", groupTitle=" + this.g + ", pageNumber=" + this.h + ", textbookMetadata=" + this.i + ")";
    }
}
