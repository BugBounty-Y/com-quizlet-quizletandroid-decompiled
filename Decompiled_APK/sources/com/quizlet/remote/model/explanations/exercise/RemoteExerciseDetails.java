package com.quizlet.remote.model.explanations.exercise;

import androidx.compose.animation.d0;
import com.quizlet.remote.model.explanations.solution.RemoteSolution;
import com.quizlet.remote.model.explanations.textbook.RemoteTextbook;
import com.quizlet.remote.model.explanations.toc.RemoteExercise;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteExerciseDetails {
    public final long a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final String g;
    public final String h;
    public final String i;
    public final String j;
    public final RemoteTextbook k;
    public final List l;
    public final List m;
    public final List n;
    public final Long o;
    public final boolean p;

    public RemoteExerciseDetails(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = "mediaExerciseId") @NotNull String mediaExerciseId, @InterfaceC4853h(name = "exerciseName") @NotNull String exercise, @InterfaceC4853h(name = "chapterName") @NotNull String chapterName, @InterfaceC4853h(name = "chapterTitle") String str, @InterfaceC4853h(name = "groupTitle") String str2, @InterfaceC4853h(name = "sectionName") String str3, @InterfaceC4853h(name = "sectionTitle") String str4, @InterfaceC4853h(name = "pageNumber") String str5, @InterfaceC4853h(name = "_webUrl") String str6, @InterfaceC4853h(name = "textbook") @NotNull RemoteTextbook textbook, @InterfaceC4853h(name = "solutions") @NotNull List<RemoteSolution> solutions, @InterfaceC4853h(name = "nextExercises") @NotNull List<RemoteExercise> nextExercises, @InterfaceC4853h(name = "previousExercises") @NotNull List<RemoteExercise> previousExercises, @InterfaceC4853h(name = "timestamp") Long l, @InterfaceC4853h(name = "isDeleted") boolean z) {
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
        this.j = str6;
        this.k = textbook;
        this.l = solutions;
        this.m = nextExercises;
        this.n = previousExercises;
        this.o = l;
        this.p = z;
    }

    @NotNull
    public final RemoteExerciseDetails copy(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = "mediaExerciseId") @NotNull String mediaExerciseId, @InterfaceC4853h(name = "exerciseName") @NotNull String exercise, @InterfaceC4853h(name = "chapterName") @NotNull String chapterName, @InterfaceC4853h(name = "chapterTitle") String str, @InterfaceC4853h(name = "groupTitle") String str2, @InterfaceC4853h(name = "sectionName") String str3, @InterfaceC4853h(name = "sectionTitle") String str4, @InterfaceC4853h(name = "pageNumber") String str5, @InterfaceC4853h(name = "_webUrl") String str6, @InterfaceC4853h(name = "textbook") @NotNull RemoteTextbook textbook, @InterfaceC4853h(name = "solutions") @NotNull List<RemoteSolution> solutions, @InterfaceC4853h(name = "nextExercises") @NotNull List<RemoteExercise> nextExercises, @InterfaceC4853h(name = "previousExercises") @NotNull List<RemoteExercise> previousExercises, @InterfaceC4853h(name = "timestamp") Long l, @InterfaceC4853h(name = "isDeleted") boolean z) {
        Intrinsics.checkNotNullParameter(mediaExerciseId, "mediaExerciseId");
        Intrinsics.checkNotNullParameter(exercise, "exercise");
        Intrinsics.checkNotNullParameter(chapterName, "chapterName");
        Intrinsics.checkNotNullParameter(textbook, "textbook");
        Intrinsics.checkNotNullParameter(solutions, "solutions");
        Intrinsics.checkNotNullParameter(nextExercises, "nextExercises");
        Intrinsics.checkNotNullParameter(previousExercises, "previousExercises");
        return new RemoteExerciseDetails(j, mediaExerciseId, exercise, chapterName, str, str2, str3, str4, str5, str6, textbook, solutions, nextExercises, previousExercises, l, z);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteExerciseDetails)) {
            return false;
        }
        RemoteExerciseDetails remoteExerciseDetails = (RemoteExerciseDetails) obj;
        return this.a == remoteExerciseDetails.a && Intrinsics.b(this.b, remoteExerciseDetails.b) && Intrinsics.b(this.c, remoteExerciseDetails.c) && Intrinsics.b(this.d, remoteExerciseDetails.d) && Intrinsics.b(this.e, remoteExerciseDetails.e) && Intrinsics.b(this.f, remoteExerciseDetails.f) && Intrinsics.b(this.g, remoteExerciseDetails.g) && Intrinsics.b(this.h, remoteExerciseDetails.h) && Intrinsics.b(this.i, remoteExerciseDetails.i) && Intrinsics.b(this.j, remoteExerciseDetails.j) && Intrinsics.b(this.k, remoteExerciseDetails.k) && Intrinsics.b(this.l, remoteExerciseDetails.l) && Intrinsics.b(this.m, remoteExerciseDetails.m) && Intrinsics.b(this.n, remoteExerciseDetails.n) && Intrinsics.b(this.o, remoteExerciseDetails.o) && this.p == remoteExerciseDetails.p;
    }

    public final int hashCode() {
        int iE = d0.e(d0.e(d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d);
        String str = this.e;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.f;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.g;
        int iHashCode3 = (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.h;
        int iHashCode4 = (iHashCode3 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.i;
        int iHashCode5 = (iHashCode4 + (str5 == null ? 0 : str5.hashCode())) * 31;
        String str6 = this.j;
        int iF = d0.f(d0.f(d0.f((this.k.hashCode() + ((iHashCode5 + (str6 == null ? 0 : str6.hashCode())) * 31)) * 31, 31, this.l), 31, this.m), 31, this.n);
        Long l = this.o;
        return Boolean.hashCode(this.p) + ((iF + (l != null ? l.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteExerciseDetails(id=");
        sb.append(this.a);
        sb.append(", mediaExerciseId=");
        sb.append(this.b);
        sb.append(", exercise=");
        sb.append(this.c);
        sb.append(", chapterName=");
        sb.append(this.d);
        sb.append(", chapterTitle=");
        sb.append(this.e);
        sb.append(", groupName=");
        sb.append(this.f);
        sb.append(", sectionName=");
        sb.append(this.g);
        sb.append(", sectionTitle=");
        sb.append(this.h);
        sb.append(", pageNumber=");
        sb.append(this.i);
        sb.append(", webUrl=");
        sb.append(this.j);
        sb.append(", textbook=");
        sb.append(this.k);
        sb.append(", solutions=");
        sb.append(this.l);
        sb.append(", nextExercises=");
        sb.append(this.m);
        sb.append(", previousExercises=");
        sb.append(this.n);
        sb.append(", timestampSec=");
        sb.append(this.o);
        sb.append(", isDeleted=");
        return android.support.v4.media.session.a.o(")", sb, this.p);
    }

    public /* synthetic */ RemoteExerciseDetails(long j, String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, String str9, RemoteTextbook remoteTextbook, List list, List list2, List list3, Long l, boolean z, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(j, str, str2, str3, str4, str5, str6, str7, str8, str9, remoteTextbook, list, list2, list3, (i & 16384) != 0 ? null : l, (i & 32768) != 0 ? false : z);
    }
}
