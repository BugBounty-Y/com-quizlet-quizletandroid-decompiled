package com.quizlet.remote.model.universaluploadflow;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.E0;
import com.quizlet.generated.enums.EnumC4483g0;
import com.quizlet.remote.model.practicetests.QuestionCompatibility;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class UploadFlashcardSetPracticeTestsBody {
    public final List a;
    public final boolean b;
    public final String c;
    public final String d;
    public final QuestionCompatibility e;

    public UploadFlashcardSetPracticeTestsBody(List setIds, boolean z, String inputType, String entryPoint, QuestionCompatibility questionCompatibility) {
        Intrinsics.checkNotNullParameter(setIds, "setIds");
        Intrinsics.checkNotNullParameter(inputType, "inputType");
        Intrinsics.checkNotNullParameter(entryPoint, "entryPoint");
        Intrinsics.checkNotNullParameter(questionCompatibility, "questionCompatibility");
        this.a = setIds;
        this.b = z;
        this.c = inputType;
        this.d = entryPoint;
        this.e = questionCompatibility;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof UploadFlashcardSetPracticeTestsBody)) {
            return false;
        }
        UploadFlashcardSetPracticeTestsBody uploadFlashcardSetPracticeTestsBody = (UploadFlashcardSetPracticeTestsBody) obj;
        return Intrinsics.b(this.a, uploadFlashcardSetPracticeTestsBody.a) && this.b == uploadFlashcardSetPracticeTestsBody.b && Intrinsics.b(this.c, uploadFlashcardSetPracticeTestsBody.c) && Intrinsics.b(this.d, uploadFlashcardSetPracticeTestsBody.d) && Intrinsics.b(this.e, uploadFlashcardSetPracticeTestsBody.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + d0.e(d0.e(d0.g(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d);
    }

    public final String toString() {
        return "UploadFlashcardSetPracticeTestsBody(setIds=" + this.a + ", private=" + this.b + ", inputType=" + this.c + ", entryPoint=" + this.d + ", questionCompatibility=" + this.e + ")";
    }

    public /* synthetic */ UploadFlashcardSetPracticeTestsBody(List list, boolean z, String str, String str2, QuestionCompatibility questionCompatibility, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(list, z, (i & 4) != 0 ? EnumC4483g0.FLASHCARD_SET.a() : str, (i & 8) != 0 ? E0.UPLOAD_PAGE.a() : str2, (i & 16) != 0 ? new QuestionCompatibility(null, null, null, 7, null) : questionCompatibility);
    }
}
