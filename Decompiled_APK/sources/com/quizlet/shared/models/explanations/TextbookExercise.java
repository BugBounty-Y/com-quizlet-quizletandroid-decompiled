package com.quizlet.shared.models.explanations;

import androidx.compose.animation.d0;
import assistantMode.refactored.a;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;
import serialization.e;

@f
@Metadata
/* loaded from: classes3.dex */
public final class TextbookExercise extends e {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final String g;
    public final boolean h;
    public final String i;
    public final String j;
    public final String k;
    public final String l;
    public final Textbook m;
    public final Boolean n;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return TextbookExercise$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ TextbookExercise(int i, long j, String str, String str2, String str3, String str4, String str5, boolean z, String str6, String str7, String str8, String str9, Textbook textbook, Boolean bool) {
        if (4095 != (i & 4095)) {
            AbstractC5047c0.k(i, 4095, TextbookExercise$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.b = j;
        this.c = str;
        this.d = str2;
        this.e = str3;
        this.f = str4;
        this.g = str5;
        this.h = z;
        this.i = str6;
        this.j = str7;
        this.k = str8;
        this.l = str9;
        this.m = textbook;
        if ((i & 4096) == 0) {
            this.n = null;
        } else {
            this.n = bool;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TextbookExercise)) {
            return false;
        }
        TextbookExercise textbookExercise = (TextbookExercise) obj;
        return this.b == textbookExercise.b && Intrinsics.b(this.c, textbookExercise.c) && Intrinsics.b(this.d, textbookExercise.d) && Intrinsics.b(this.e, textbookExercise.e) && Intrinsics.b(this.f, textbookExercise.f) && Intrinsics.b(this.g, textbookExercise.g) && this.h == textbookExercise.h && Intrinsics.b(this.i, textbookExercise.i) && Intrinsics.b(this.j, textbookExercise.j) && Intrinsics.b(this.k, textbookExercise.k) && Intrinsics.b(this.l, textbookExercise.l) && Intrinsics.b(this.m, textbookExercise.m) && Intrinsics.b(this.n, textbookExercise.n);
    }

    public final int hashCode() {
        int iE = d0.e(d0.e(d0.e(Long.hashCode(this.b) * 31, 31, this.c), 31, this.d), 31, this.e);
        String str = this.f;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.g;
        int iG = d0.g((iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31, 31, this.h);
        String str3 = this.i;
        int iHashCode2 = (iG + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.j;
        int iHashCode3 = (iHashCode2 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.k;
        int iHashCode4 = (iHashCode3 + (str5 == null ? 0 : str5.hashCode())) * 31;
        String str6 = this.l;
        int iHashCode5 = (this.m.hashCode() + ((iHashCode4 + (str6 == null ? 0 : str6.hashCode())) * 31)) * 31;
        Boolean bool = this.n;
        return iHashCode5 + (bool != null ? bool.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TextbookExercise(id=");
        sb.append(this.b);
        sb.append(", exerciseName=");
        sb.append(this.c);
        sb.append(", mediaExerciseId=");
        sb.append(this.d);
        sb.append(", chapterName=");
        sb.append(this.e);
        sb.append(", chapterTitle=");
        sb.append(this.f);
        sb.append(", groupTitle=");
        sb.append(this.g);
        sb.append(", isPremium=");
        sb.append(this.h);
        sb.append(", sectionName=");
        sb.append(this.i);
        sb.append(", sectionTitle=");
        sb.append(this.j);
        sb.append(", pageNumber=");
        sb.append(this.k);
        sb.append(", webUrl=");
        sb.append(this.l);
        sb.append(", textbook=");
        sb.append(this.m);
        sb.append(", isDeleted=");
        return a.k(sb, this.n, ")");
    }
}
