package com.quizlet.remote.model.explanations.question;

import androidx.compose.animation.d0;
import com.google.android.gms.ads.g;
import com.quizlet.remote.model.explanations.solution.RemoteSolution;
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
public final class RemoteQuestion {
    public final long a;
    public final String b;
    public final String c;
    public final RemoteQuestionPrompt d;
    public final String e;
    public final Integer f;
    public final List g;
    public final String h;
    public final List i;
    public final Long j;
    public final boolean k;

    public RemoteQuestion(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = "slug") @NotNull String slug, @InterfaceC4853h(name = "mediaExerciseId") String str, @InterfaceC4853h(name = "prompt") @NotNull RemoteQuestionPrompt prompt, @InterfaceC4853h(name = "questionUuid") @NotNull String questionUuid, @InterfaceC4853h(name = "answersCount") Integer num, @InterfaceC4853h(name = "subjectIds") @NotNull List<Integer> subjectIds, @InterfaceC4853h(name = "_webUrl") String str2, @InterfaceC4853h(name = "solutions") @NotNull List<RemoteSolution> solutions, @InterfaceC4853h(name = "timestamp") Long l, @InterfaceC4853h(name = "isDeleted") boolean z) {
        Intrinsics.checkNotNullParameter(slug, "slug");
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(questionUuid, "questionUuid");
        Intrinsics.checkNotNullParameter(subjectIds, "subjectIds");
        Intrinsics.checkNotNullParameter(solutions, "solutions");
        this.a = j;
        this.b = slug;
        this.c = str;
        this.d = prompt;
        this.e = questionUuid;
        this.f = num;
        this.g = subjectIds;
        this.h = str2;
        this.i = solutions;
        this.j = l;
        this.k = z;
    }

    @NotNull
    public final RemoteQuestion copy(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = "slug") @NotNull String slug, @InterfaceC4853h(name = "mediaExerciseId") String str, @InterfaceC4853h(name = "prompt") @NotNull RemoteQuestionPrompt prompt, @InterfaceC4853h(name = "questionUuid") @NotNull String questionUuid, @InterfaceC4853h(name = "answersCount") Integer num, @InterfaceC4853h(name = "subjectIds") @NotNull List<Integer> subjectIds, @InterfaceC4853h(name = "_webUrl") String str2, @InterfaceC4853h(name = "solutions") @NotNull List<RemoteSolution> solutions, @InterfaceC4853h(name = "timestamp") Long l, @InterfaceC4853h(name = "isDeleted") boolean z) {
        Intrinsics.checkNotNullParameter(slug, "slug");
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(questionUuid, "questionUuid");
        Intrinsics.checkNotNullParameter(subjectIds, "subjectIds");
        Intrinsics.checkNotNullParameter(solutions, "solutions");
        return new RemoteQuestion(j, slug, str, prompt, questionUuid, num, subjectIds, str2, solutions, l, z);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteQuestion)) {
            return false;
        }
        RemoteQuestion remoteQuestion = (RemoteQuestion) obj;
        return this.a == remoteQuestion.a && Intrinsics.b(this.b, remoteQuestion.b) && Intrinsics.b(this.c, remoteQuestion.c) && Intrinsics.b(this.d, remoteQuestion.d) && Intrinsics.b(this.e, remoteQuestion.e) && Intrinsics.b(this.f, remoteQuestion.f) && Intrinsics.b(this.g, remoteQuestion.g) && Intrinsics.b(this.h, remoteQuestion.h) && Intrinsics.b(this.i, remoteQuestion.i) && Intrinsics.b(this.j, remoteQuestion.j) && this.k == remoteQuestion.k;
    }

    public final int hashCode() {
        int iE = d0.e(Long.hashCode(this.a) * 31, 31, this.b);
        String str = this.c;
        int iE2 = d0.e((this.d.hashCode() + ((iE + (str == null ? 0 : str.hashCode())) * 31)) * 31, 31, this.e);
        Integer num = this.f;
        int iF = d0.f((iE2 + (num == null ? 0 : num.hashCode())) * 31, 31, this.g);
        String str2 = this.h;
        int iF2 = d0.f((iF + (str2 == null ? 0 : str2.hashCode())) * 31, 31, this.i);
        Long l = this.j;
        return Boolean.hashCode(this.k) + ((iF2 + (l != null ? l.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteQuestion(id=");
        sb.append(this.a);
        sb.append(", slug=");
        sb.append(this.b);
        sb.append(", mediaExerciseId=");
        sb.append(this.c);
        sb.append(", prompt=");
        sb.append(this.d);
        sb.append(", questionUuid=");
        sb.append(this.e);
        sb.append(", answersCount=");
        sb.append(this.f);
        sb.append(", subjectIds=");
        sb.append(this.g);
        sb.append(", webUrl=");
        sb.append(this.h);
        sb.append(", solutions=");
        sb.append(this.i);
        sb.append(", timestampSec=");
        sb.append(this.j);
        sb.append(", isDeleted=");
        return android.support.v4.media.session.a.o(")", sb, this.k);
    }

    public /* synthetic */ RemoteQuestion(long j, String str, String str2, RemoteQuestionPrompt remoteQuestionPrompt, String str3, Integer num, List list, String str4, List list2, Long l, boolean z, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(j, str, str2, remoteQuestionPrompt, str3, num, list, str4, list2, (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : l, (i & 1024) != 0 ? false : z);
    }
}
