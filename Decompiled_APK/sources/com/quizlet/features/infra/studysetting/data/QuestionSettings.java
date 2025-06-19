package com.quizlet.features.infra.studysetting.data;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import assistantMode.enums.k;
import assistantMode.enums.y;
import com.google.android.gms.ads.g;
import com.quizlet.generated.enums.O1;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class QuestionSettings implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<QuestionSettings> CREATOR = new a(1);
    public final List a;
    public final List b;
    public final boolean c;
    public final boolean d;
    public final boolean e;
    public final boolean f;
    public final boolean g;
    public final boolean h;
    public final boolean i;
    public final Long j;
    public final Long k;
    public final com.quizlet.studiablemodels.assistantMode.a l;
    public final y m;
    public final boolean n;
    public final boolean o;
    public final boolean p;
    public final boolean q;
    public final boolean r;
    public final ArrayList s;

    public QuestionSettings(List enabledPromptSides, List enabledAnswerSides, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6, boolean z7, Long l, Long l2, com.quizlet.studiablemodels.assistantMode.a aVar, y yVar, boolean z8, boolean z9, boolean z10, boolean z11, boolean z12) {
        Intrinsics.checkNotNullParameter(enabledPromptSides, "enabledPromptSides");
        Intrinsics.checkNotNullParameter(enabledAnswerSides, "enabledAnswerSides");
        this.a = enabledPromptSides;
        this.b = enabledAnswerSides;
        this.c = z;
        this.d = z2;
        this.e = z3;
        this.f = z4;
        this.g = z5;
        this.h = z6;
        this.i = z7;
        this.j = l;
        this.k = l2;
        this.l = aVar;
        this.m = yVar;
        this.n = z8;
        this.o = z9;
        this.p = z10;
        this.q = z11;
        this.r = z12;
        ArrayList arrayList = new ArrayList(3);
        if (z2) {
            arrayList.add(k.f);
        }
        if (z3) {
            arrayList.add(k.d);
        }
        if (z4) {
            arrayList.add(k.b);
        }
        if (z5) {
            arrayList.add(k.l);
        }
        this.s = arrayList;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v34, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r2v35, types: [java.util.List] */
    public static QuestionSettings a(QuestionSettings questionSettings, ArrayList arrayList, ArrayList arrayList2, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6, boolean z7, Long l, Long l2, boolean z8, boolean z9, boolean z10, boolean z11, boolean z12, int i) {
        ArrayList enabledPromptSides = (i & 1) != 0 ? questionSettings.a : arrayList;
        ArrayList enabledAnswerSides = (i & 2) != 0 ? questionSettings.b : arrayList2;
        boolean z13 = (i & 4) != 0 ? questionSettings.c : z;
        boolean z14 = (i & 8) != 0 ? questionSettings.d : z2;
        boolean z15 = (i & 16) != 0 ? questionSettings.e : z3;
        boolean z16 = (i & 32) != 0 ? questionSettings.f : z4;
        boolean z17 = (i & 64) != 0 ? questionSettings.g : z5;
        boolean z18 = (i & 128) != 0 ? questionSettings.h : z6;
        boolean z19 = (i & 256) != 0 ? questionSettings.i : z7;
        Long l3 = (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? questionSettings.j : l;
        Long l4 = (i & 1024) != 0 ? questionSettings.k : l2;
        com.quizlet.studiablemodels.assistantMode.a aVar = (i & 2048) != 0 ? questionSettings.l : null;
        y yVar = (i & 4096) != 0 ? questionSettings.m : null;
        boolean z20 = (i & 8192) != 0 ? questionSettings.n : z8;
        boolean z21 = (i & 16384) != 0 ? questionSettings.o : z9;
        boolean z22 = (32768 & i) != 0 ? questionSettings.p : z10;
        boolean z23 = (65536 & i) != 0 ? questionSettings.q : z11;
        boolean z24 = (i & 131072) != 0 ? questionSettings.r : z12;
        questionSettings.getClass();
        Intrinsics.checkNotNullParameter(enabledPromptSides, "enabledPromptSides");
        Intrinsics.checkNotNullParameter(enabledAnswerSides, "enabledAnswerSides");
        return new QuestionSettings(enabledPromptSides, enabledAnswerSides, z13, z14, z15, z16, z17, z18, z19, l3, l4, aVar, yVar, z20, z21, z22, z23, z24);
    }

    public final boolean b() {
        return this.b.contains(O1.LOCATION);
    }

    public final boolean c() {
        return this.b.contains(O1.WORD);
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof QuestionSettings)) {
            return false;
        }
        QuestionSettings questionSettings = (QuestionSettings) obj;
        return Intrinsics.b(this.a, questionSettings.a) && Intrinsics.b(this.b, questionSettings.b) && this.c == questionSettings.c && this.d == questionSettings.d && this.e == questionSettings.e && this.f == questionSettings.f && this.g == questionSettings.g && this.h == questionSettings.h && this.i == questionSettings.i && Intrinsics.b(this.j, questionSettings.j) && Intrinsics.b(this.k, questionSettings.k) && this.l == questionSettings.l && this.m == questionSettings.m && this.n == questionSettings.n && this.o == questionSettings.o && this.p == questionSettings.p && this.q == questionSettings.q && this.r == questionSettings.r;
    }

    public final int hashCode() {
        int iG = d0.g(d0.g(d0.g(d0.g(d0.g(d0.g(d0.g(d0.f(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g), 31, this.h), 31, this.i);
        Long l = this.j;
        int iHashCode = (iG + (l == null ? 0 : l.hashCode())) * 31;
        Long l2 = this.k;
        int iHashCode2 = (iHashCode + (l2 == null ? 0 : l2.hashCode())) * 31;
        com.quizlet.studiablemodels.assistantMode.a aVar = this.l;
        int iHashCode3 = (iHashCode2 + (aVar == null ? 0 : aVar.hashCode())) * 31;
        y yVar = this.m;
        return Boolean.hashCode(this.r) + d0.g(d0.g(d0.g(d0.g((iHashCode3 + (yVar != null ? yVar.hashCode() : 0)) * 31, 31, this.n), 31, this.o), 31, this.p), 31, this.q);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("QuestionSettings(enabledPromptSides=");
        sb.append(this.a);
        sb.append(", enabledAnswerSides=");
        sb.append(this.b);
        sb.append(", audioEnabled=");
        sb.append(this.c);
        sb.append(", selfAssessmentQuestionsEnabled=");
        sb.append(this.d);
        sb.append(", multipleChoiceQuestionsEnabled=");
        sb.append(this.e);
        sb.append(", writtenQuestionsEnabled=");
        sb.append(this.f);
        sb.append(", fillInTheBlankQuestionsEnabled=");
        sb.append(this.g);
        sb.append(", writtenPromptTermSideEnabled=");
        sb.append(this.h);
        sb.append(", writtenPromptDefinitionSideEnabled=");
        sb.append(this.i);
        sb.append(", testDateMs=");
        sb.append(this.j);
        sb.append(", startDateMs=");
        sb.append(this.k);
        sb.append(", studyPathGoal=");
        sb.append(this.l);
        sb.append(", studyPathKnowledgeLevel=");
        sb.append(this.m);
        sb.append(", flexibleGradingPartialAnswersEnabled=");
        sb.append(this.n);
        sb.append(", smartGradingEnabled=");
        sb.append(this.o);
        sb.append(", typoCorrectionEnabled=");
        sb.append(this.p);
        sb.append(", shuffleTermsEnabled=");
        sb.append(this.q);
        sb.append(", copyAnswerEnabled=");
        return android.support.v4.media.session.a.o(")", sb, this.r);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        List list = this.a;
        dest.writeInt(list.size());
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            dest.writeString(((O1) it2.next()).name());
        }
        List list2 = this.b;
        dest.writeInt(list2.size());
        Iterator it3 = list2.iterator();
        while (it3.hasNext()) {
            dest.writeString(((O1) it3.next()).name());
        }
        dest.writeInt(this.c ? 1 : 0);
        dest.writeInt(this.d ? 1 : 0);
        dest.writeInt(this.e ? 1 : 0);
        dest.writeInt(this.f ? 1 : 0);
        dest.writeInt(this.g ? 1 : 0);
        dest.writeInt(this.h ? 1 : 0);
        dest.writeInt(this.i ? 1 : 0);
        Long l = this.j;
        if (l == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeLong(l.longValue());
        }
        Long l2 = this.k;
        if (l2 == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeLong(l2.longValue());
        }
        com.quizlet.studiablemodels.assistantMode.a aVar = this.l;
        if (aVar == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeString(aVar.name());
        }
        y yVar = this.m;
        if (yVar == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeString(yVar.name());
        }
        dest.writeInt(this.n ? 1 : 0);
        dest.writeInt(this.o ? 1 : 0);
        dest.writeInt(this.p ? 1 : 0);
        dest.writeInt(this.q ? 1 : 0);
        dest.writeInt(this.r ? 1 : 0);
    }
}
