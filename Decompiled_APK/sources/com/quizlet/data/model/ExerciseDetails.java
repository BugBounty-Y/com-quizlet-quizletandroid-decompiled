package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_document_scanner.E6;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class ExerciseDetails extends E6 {
    public final long a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final String g;
    public final String h;
    public final String i;
    public final Textbook j;
    public final List k;
    public final List l;
    public final List m;
    public final String n;

    public ExerciseDetails(long j, String mediaExerciseId, String exercise, String chapterName, String str, String str2, String str3, String str4, String str5, Textbook textbook, List solutions, List nextExercises, List previousExercises, String str6) {
        Intrinsics.checkNotNullParameter(mediaExerciseId, "mediaExerciseId");
        Intrinsics.checkNotNullParameter(exercise, "exercise");
        Intrinsics.checkNotNullParameter(chapterName, "chapterName");
        Intrinsics.checkNotNullParameter(textbook, "textbook");
        Intrinsics.checkNotNullParameter(solutions, "solutions");
        Intrinsics.checkNotNullParameter(nextExercises, "nextExercises");
        Intrinsics.checkNotNullParameter(previousExercises, "previousExercises");
        this.a = j;
        this.b = mediaExerciseId;
        this.c = exercise;
        this.d = chapterName;
        this.e = str;
        this.f = str2;
        this.g = str3;
        this.h = str4;
        this.i = str5;
        this.j = textbook;
        this.k = solutions;
        this.l = nextExercises;
        this.m = previousExercises;
        this.n = str6;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ExerciseDetails)) {
            return false;
        }
        ExerciseDetails exerciseDetails = (ExerciseDetails) obj;
        return this.a == exerciseDetails.a && Intrinsics.b(this.b, exerciseDetails.b) && Intrinsics.b(this.c, exerciseDetails.c) && Intrinsics.b(this.d, exerciseDetails.d) && Intrinsics.b(this.e, exerciseDetails.e) && Intrinsics.b(this.f, exerciseDetails.f) && Intrinsics.b(this.g, exerciseDetails.g) && Intrinsics.b(this.h, exerciseDetails.h) && Intrinsics.b(this.i, exerciseDetails.i) && Intrinsics.b(this.j, exerciseDetails.j) && Intrinsics.b(this.k, exerciseDetails.k) && Intrinsics.b(this.l, exerciseDetails.l) && Intrinsics.b(this.m, exerciseDetails.m) && Intrinsics.b(this.n, exerciseDetails.n);
    }

    public final int hashCode() {
        int iE = androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d);
        String str = this.e;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.f;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.g;
        int iHashCode3 = (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.h;
        int iHashCode4 = (iHashCode3 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.i;
        int iF = androidx.compose.animation.d0.f(androidx.compose.animation.d0.f(androidx.compose.animation.d0.f((this.j.hashCode() + ((iHashCode4 + (str5 == null ? 0 : str5.hashCode())) * 31)) * 31, 31, this.k), 31, this.l), 31, this.m);
        String str6 = this.n;
        return iF + (str6 != null ? str6.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExerciseDetails(id=");
        sb.append(this.a);
        sb.append(", mediaExerciseId=");
        sb.append(this.b);
        sb.append(", exercise=");
        sb.append(this.c);
        sb.append(", chapterName=");
        sb.append(this.d);
        sb.append(", groupName=");
        sb.append(this.e);
        sb.append(", sectionName=");
        sb.append(this.f);
        sb.append(", chapterTitle=");
        sb.append(this.g);
        sb.append(", sectionTitle=");
        sb.append(this.h);
        sb.append(", pageNumber=");
        sb.append(this.i);
        sb.append(", textbook=");
        sb.append(this.j);
        sb.append(", solutions=");
        sb.append(this.k);
        sb.append(", nextExercises=");
        sb.append(this.l);
        sb.append(", previousExercises=");
        sb.append(this.m);
        sb.append(", webUrl=");
        return android.support.v4.media.session.a.t(sb, this.n, ")");
    }
}
