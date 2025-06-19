package com.quizlet.remote.model.practicetests;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class QuestionBanksModel {
    public final String a;
    public final String b;
    public final String c;
    public final Boolean d;
    public final long e;
    public final String f;
    public final String g;
    public final String h;

    public QuestionBanksModel(String questionBankUuid, String name, String createdAt, Boolean bool, long j, String documentType, String str, String str2) {
        Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(createdAt, "createdAt");
        Intrinsics.checkNotNullParameter(documentType, "documentType");
        this.a = questionBankUuid;
        this.b = name;
        this.c = createdAt;
        this.d = bool;
        this.e = j;
        this.f = documentType;
        this.g = str;
        this.h = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof QuestionBanksModel)) {
            return false;
        }
        QuestionBanksModel questionBanksModel = (QuestionBanksModel) obj;
        return Intrinsics.b(this.a, questionBanksModel.a) && Intrinsics.b(this.b, questionBanksModel.b) && Intrinsics.b(this.c, questionBanksModel.c) && Intrinsics.b(this.d, questionBanksModel.d) && this.e == questionBanksModel.e && Intrinsics.b(this.f, questionBanksModel.f) && Intrinsics.b(this.g, questionBanksModel.g) && Intrinsics.b(this.h, questionBanksModel.h);
    }

    public final int hashCode() {
        int iE = d0.e(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c);
        Boolean bool = this.d;
        int iE2 = d0.e(d0.d((iE + (bool == null ? 0 : bool.hashCode())) * 31, 31, this.e), 31, this.f);
        String str = this.g;
        int iHashCode = (iE2 + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.h;
        return iHashCode + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("QuestionBanksModel(questionBankUuid=");
        sb.append(this.a);
        sb.append(", name=");
        sb.append(this.b);
        sb.append(", createdAt=");
        sb.append(this.c);
        sb.append(", private=");
        sb.append(this.d);
        sb.append(", creatorId=");
        sb.append(this.e);
        sb.append(", documentType=");
        sb.append(this.f);
        sb.append(", fileName=");
        sb.append(this.g);
        sb.append(", uploadEntryPoint=");
        return android.support.v4.media.session.a.t(sb, this.h, ")");
    }

    public /* synthetic */ QuestionBanksModel(String str, String str2, String str3, Boolean bool, long j, String str4, String str5, String str6, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, str2, str3, (i & 8) != 0 ? null : bool, j, str4, (i & 64) != 0 ? null : str5, (i & 128) != 0 ? null : str6);
    }
}
