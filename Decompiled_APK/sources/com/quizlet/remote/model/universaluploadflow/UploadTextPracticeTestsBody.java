package com.quizlet.remote.model.universaluploadflow;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.EnumC4483g0;
import com.quizlet.remote.model.practicetests.QuestionCompatibility;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class UploadTextPracticeTestsBody {
    public final String a;
    public final boolean b;
    public final QuestionCompatibility c;
    public final String d;

    public UploadTextPracticeTestsBody(String text, boolean z, QuestionCompatibility questionCompatibility, String inputType) {
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(questionCompatibility, "questionCompatibility");
        Intrinsics.checkNotNullParameter(inputType, "inputType");
        this.a = text;
        this.b = z;
        this.c = questionCompatibility;
        this.d = inputType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof UploadTextPracticeTestsBody)) {
            return false;
        }
        UploadTextPracticeTestsBody uploadTextPracticeTestsBody = (UploadTextPracticeTestsBody) obj;
        return Intrinsics.b(this.a, uploadTextPracticeTestsBody.a) && this.b == uploadTextPracticeTestsBody.b && Intrinsics.b(this.c, uploadTextPracticeTestsBody.c) && Intrinsics.b(this.d, uploadTextPracticeTestsBody.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + ((this.c.hashCode() + d0.g(this.a.hashCode() * 31, 31, this.b)) * 31);
    }

    public final String toString() {
        return "UploadTextPracticeTestsBody(text=" + this.a + ", private=" + this.b + ", questionCompatibility=" + this.c + ", inputType=" + this.d + ")";
    }

    public /* synthetic */ UploadTextPracticeTestsBody(String str, boolean z, QuestionCompatibility questionCompatibility, String str2, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, z, (i & 4) != 0 ? new QuestionCompatibility(null, null, null, 7, null) : questionCompatibility, (i & 8) != 0 ? EnumC4483g0.TEXT.a() : str2);
    }
}
