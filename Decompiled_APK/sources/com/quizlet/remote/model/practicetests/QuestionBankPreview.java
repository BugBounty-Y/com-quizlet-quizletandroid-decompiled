package com.quizlet.remote.model.practicetests;

import androidx.compose.animation.d0;
import com.quizlet.remote.model.user.RemoteFullUser;
import com.squareup.moshi.m;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class QuestionBankPreview {
    public final String a;
    public final String b;
    public final String c;
    public final List d;
    public final String e;
    public final PracticeTestCourse f;
    public final PracticeTestSchool g;
    public final RemoteFullUser h;
    public final QuestionBankMetadataResponse i;
    public final boolean j;
    public final Map k;

    public QuestionBankPreview(String id, String name, String nameSlug, List questions, String createdAt, PracticeTestCourse practiceTestCourse, PracticeTestSchool practiceTestSchool, RemoteFullUser remoteFullUser, QuestionBankMetadataResponse questionBankMetadataResponse, boolean z, Map questionCounts) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(nameSlug, "nameSlug");
        Intrinsics.checkNotNullParameter(questions, "questions");
        Intrinsics.checkNotNullParameter(createdAt, "createdAt");
        Intrinsics.checkNotNullParameter(questionCounts, "questionCounts");
        this.a = id;
        this.b = name;
        this.c = nameSlug;
        this.d = questions;
        this.e = createdAt;
        this.f = practiceTestCourse;
        this.g = practiceTestSchool;
        this.h = remoteFullUser;
        this.i = questionBankMetadataResponse;
        this.j = z;
        this.k = questionCounts;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof QuestionBankPreview)) {
            return false;
        }
        QuestionBankPreview questionBankPreview = (QuestionBankPreview) obj;
        return Intrinsics.b(this.a, questionBankPreview.a) && Intrinsics.b(this.b, questionBankPreview.b) && Intrinsics.b(this.c, questionBankPreview.c) && Intrinsics.b(this.d, questionBankPreview.d) && Intrinsics.b(this.e, questionBankPreview.e) && Intrinsics.b(this.f, questionBankPreview.f) && Intrinsics.b(this.g, questionBankPreview.g) && Intrinsics.b(this.h, questionBankPreview.h) && Intrinsics.b(this.i, questionBankPreview.i) && this.j == questionBankPreview.j && Intrinsics.b(this.k, questionBankPreview.k);
    }

    public final int hashCode() {
        int iE = d0.e(d0.f(d0.e(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e);
        PracticeTestCourse practiceTestCourse = this.f;
        int iHashCode = (iE + (practiceTestCourse == null ? 0 : practiceTestCourse.hashCode())) * 31;
        PracticeTestSchool practiceTestSchool = this.g;
        int iHashCode2 = (iHashCode + (practiceTestSchool == null ? 0 : practiceTestSchool.hashCode())) * 31;
        RemoteFullUser remoteFullUser = this.h;
        int iHashCode3 = (iHashCode2 + (remoteFullUser == null ? 0 : remoteFullUser.hashCode())) * 31;
        QuestionBankMetadataResponse questionBankMetadataResponse = this.i;
        return this.k.hashCode() + d0.g((iHashCode3 + (questionBankMetadataResponse != null ? questionBankMetadataResponse.hashCode() : 0)) * 31, 31, this.j);
    }

    public final String toString() {
        return "QuestionBankPreview(id=" + this.a + ", name=" + this.b + ", nameSlug=" + this.c + ", questions=" + this.d + ", createdAt=" + this.e + ", course=" + this.f + ", school=" + this.g + ", creator=" + this.h + ", metadata=" + this.i + ", private=" + this.j + ", questionCounts=" + this.k + ")";
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public /* synthetic */ QuestionBankPreview(String str, String str2, String str3, List list, String str4, PracticeTestCourse practiceTestCourse, PracticeTestSchool practiceTestSchool, RemoteFullUser remoteFullUser, QuestionBankMetadataResponse questionBankMetadataResponse, boolean z, Map map, int i, DefaultConstructorMarker defaultConstructorMarker) {
        Map map2;
        boolean z2;
        QuestionBankMetadataResponse questionBankMetadataResponse2;
        practiceTestCourse = (i & 32) != 0 ? null : practiceTestCourse;
        practiceTestSchool = (i & 64) != 0 ? null : practiceTestSchool;
        remoteFullUser = (i & 128) != 0 ? null : remoteFullUser;
        if ((i & 256) != 0) {
            map2 = map;
            z2 = z;
            questionBankMetadataResponse2 = null;
        } else {
            map2 = map;
            z2 = z;
            questionBankMetadataResponse2 = questionBankMetadataResponse;
        }
        this(str, str2, str3, list, str4, practiceTestCourse, practiceTestSchool, remoteFullUser, questionBankMetadataResponse2, z2, map2);
    }
}
