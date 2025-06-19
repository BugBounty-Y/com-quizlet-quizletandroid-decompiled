package com.quizlet.shared.models.api.explanations;

import assistantMode.refactored.a;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class RemoteTextbookExercise {

    @NotNull
    public static final Companion Companion = new Companion();
    public final Long a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final String g;
    public final String h;
    public final String i;
    public final Boolean j;
    public final String k;
    public final RemoteTextbook l;
    public final Long m;
    public final Long n;
    public final Boolean o;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return RemoteTextbookExercise$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ RemoteTextbookExercise(int i, Long l, String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, Boolean bool, String str9, RemoteTextbook remoteTextbook, Long l2, Long l3, Boolean bool2) {
        if (16383 != (i & 16383)) {
            AbstractC5047c0.k(i, 16383, RemoteTextbookExercise$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = l;
        this.b = str;
        this.c = str2;
        this.d = str3;
        this.e = str4;
        this.f = str5;
        this.g = str6;
        this.h = str7;
        this.i = str8;
        this.j = bool;
        this.k = str9;
        this.l = remoteTextbook;
        this.m = l2;
        this.n = l3;
        if ((i & 16384) == 0) {
            this.o = null;
        } else {
            this.o = bool2;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteTextbookExercise)) {
            return false;
        }
        RemoteTextbookExercise remoteTextbookExercise = (RemoteTextbookExercise) obj;
        return Intrinsics.b(this.a, remoteTextbookExercise.a) && Intrinsics.b(this.b, remoteTextbookExercise.b) && Intrinsics.b(this.c, remoteTextbookExercise.c) && Intrinsics.b(this.d, remoteTextbookExercise.d) && Intrinsics.b(this.e, remoteTextbookExercise.e) && Intrinsics.b(this.f, remoteTextbookExercise.f) && Intrinsics.b(this.g, remoteTextbookExercise.g) && Intrinsics.b(this.h, remoteTextbookExercise.h) && Intrinsics.b(this.i, remoteTextbookExercise.i) && Intrinsics.b(this.j, remoteTextbookExercise.j) && Intrinsics.b(this.k, remoteTextbookExercise.k) && Intrinsics.b(this.l, remoteTextbookExercise.l) && Intrinsics.b(this.m, remoteTextbookExercise.m) && Intrinsics.b(this.n, remoteTextbookExercise.n) && Intrinsics.b(this.o, remoteTextbookExercise.o);
    }

    public final int hashCode() {
        Long l = this.a;
        int iHashCode = (l == null ? 0 : l.hashCode()) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.c;
        int iHashCode3 = (iHashCode2 + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.d;
        int iHashCode4 = (iHashCode3 + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.e;
        int iHashCode5 = (iHashCode4 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.f;
        int iHashCode6 = (iHashCode5 + (str5 == null ? 0 : str5.hashCode())) * 31;
        String str6 = this.g;
        int iHashCode7 = (iHashCode6 + (str6 == null ? 0 : str6.hashCode())) * 31;
        String str7 = this.h;
        int iHashCode8 = (iHashCode7 + (str7 == null ? 0 : str7.hashCode())) * 31;
        String str8 = this.i;
        int iHashCode9 = (iHashCode8 + (str8 == null ? 0 : str8.hashCode())) * 31;
        Boolean bool = this.j;
        int iHashCode10 = (iHashCode9 + (bool == null ? 0 : bool.hashCode())) * 31;
        String str9 = this.k;
        int iHashCode11 = (iHashCode10 + (str9 == null ? 0 : str9.hashCode())) * 31;
        RemoteTextbook remoteTextbook = this.l;
        int iHashCode12 = (iHashCode11 + (remoteTextbook == null ? 0 : remoteTextbook.hashCode())) * 31;
        Long l2 = this.m;
        int iHashCode13 = (iHashCode12 + (l2 == null ? 0 : l2.hashCode())) * 31;
        Long l3 = this.n;
        int iHashCode14 = (iHashCode13 + (l3 == null ? 0 : l3.hashCode())) * 31;
        Boolean bool2 = this.o;
        return iHashCode14 + (bool2 != null ? bool2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteTextbookExercise(id=");
        sb.append(this.a);
        sb.append(", mediaExerciseId=");
        sb.append(this.b);
        sb.append(", exerciseName=");
        sb.append(this.c);
        sb.append(", chapterName=");
        sb.append(this.d);
        sb.append(", chapterTitle=");
        sb.append(this.e);
        sb.append(", groupTitle=");
        sb.append(this.f);
        sb.append(", sectionName=");
        sb.append(this.g);
        sb.append(", sectionTitle=");
        sb.append(this.h);
        sb.append(", pageNumber=");
        sb.append(this.i);
        sb.append(", isPremium=");
        sb.append(this.j);
        sb.append(", webUrl=");
        sb.append(this.k);
        sb.append(", textbook=");
        sb.append(this.l);
        sb.append(", timestamp=");
        sb.append(this.m);
        sb.append(", lastModified=");
        sb.append(this.n);
        sb.append(", isDeleted=");
        return a.k(sb, this.o, ")");
    }
}
