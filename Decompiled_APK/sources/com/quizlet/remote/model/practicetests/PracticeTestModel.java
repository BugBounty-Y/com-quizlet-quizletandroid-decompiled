package com.quizlet.remote.model.practicetests;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PracticeTestModel {
    public final String a;
    public final String b;
    public final String c;
    public final long d;
    public final String e;
    public final String f;
    public final PracticeTestConfigurationResponse g;
    public final List h;

    public PracticeTestModel(String practiceTestUuid, String name, String nameSlug, long j, String questionBankUuid, String questionBankName, PracticeTestConfigurationResponse configuration, List questions) {
        Intrinsics.checkNotNullParameter(practiceTestUuid, "practiceTestUuid");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(nameSlug, "nameSlug");
        Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
        Intrinsics.checkNotNullParameter(questionBankName, "questionBankName");
        Intrinsics.checkNotNullParameter(configuration, "configuration");
        Intrinsics.checkNotNullParameter(questions, "questions");
        this.a = practiceTestUuid;
        this.b = name;
        this.c = nameSlug;
        this.d = j;
        this.e = questionBankUuid;
        this.f = questionBankName;
        this.g = configuration;
        this.h = questions;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PracticeTestModel)) {
            return false;
        }
        PracticeTestModel practiceTestModel = (PracticeTestModel) obj;
        return Intrinsics.b(this.a, practiceTestModel.a) && Intrinsics.b(this.b, practiceTestModel.b) && Intrinsics.b(this.c, practiceTestModel.c) && this.d == practiceTestModel.d && Intrinsics.b(this.e, practiceTestModel.e) && Intrinsics.b(this.f, practiceTestModel.f) && Intrinsics.b(this.g, practiceTestModel.g) && Intrinsics.b(this.h, practiceTestModel.h);
    }

    public final int hashCode() {
        return this.h.hashCode() + ((this.g.hashCode() + d0.e(d0.e(d0.d(d0.e(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestModel(practiceTestUuid=");
        sb.append(this.a);
        sb.append(", name=");
        sb.append(this.b);
        sb.append(", nameSlug=");
        sb.append(this.c);
        sb.append(", userId=");
        sb.append(this.d);
        sb.append(", questionBankUuid=");
        sb.append(this.e);
        sb.append(", questionBankName=");
        sb.append(this.f);
        sb.append(", configuration=");
        sb.append(this.g);
        sb.append(", questions=");
        return android.support.v4.media.session.a.n(")", sb, this.h);
    }
}
