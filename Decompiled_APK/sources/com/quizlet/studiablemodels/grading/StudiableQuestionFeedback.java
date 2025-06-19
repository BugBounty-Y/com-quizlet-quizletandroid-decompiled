package com.quizlet.studiablemodels.grading;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.studiablemodels.QuestionSectionData;
import com.quizlet.studiablemodels.f;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudiableQuestionFeedback implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<StudiableQuestionFeedback> CREATOR = new f(28);
    public final StudiableQuestionResponse a;
    public final StudiableQuestionResponse b;
    public final QuestionSectionData c;
    public final LinkedHashMap d;

    public StudiableQuestionFeedback(StudiableQuestionResponse studiableQuestionResponse, StudiableQuestionResponse expectedResponse, QuestionSectionData expectedResponseData, LinkedHashMap linkedHashMap) {
        Intrinsics.checkNotNullParameter(expectedResponse, "expectedResponse");
        Intrinsics.checkNotNullParameter(expectedResponseData, "expectedResponseData");
        this.a = studiableQuestionResponse;
        this.b = expectedResponse;
        this.c = expectedResponseData;
        this.d = linkedHashMap;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudiableQuestionFeedback)) {
            return false;
        }
        StudiableQuestionFeedback studiableQuestionFeedback = (StudiableQuestionFeedback) obj;
        return Intrinsics.b(this.a, studiableQuestionFeedback.a) && Intrinsics.b(this.b, studiableQuestionFeedback.b) && Intrinsics.b(this.c, studiableQuestionFeedback.c) && Intrinsics.b(this.d, studiableQuestionFeedback.d);
    }

    public final int hashCode() {
        StudiableQuestionResponse studiableQuestionResponse = this.a;
        int iHashCode = (this.c.hashCode() + ((this.b.hashCode() + ((studiableQuestionResponse == null ? 0 : studiableQuestionResponse.hashCode()) * 31)) * 31)) * 31;
        LinkedHashMap linkedHashMap = this.d;
        return iHashCode + (linkedHashMap != null ? linkedHashMap.hashCode() : 0);
    }

    public final String toString() {
        return "StudiableQuestionFeedback(submittedResponse=" + this.a + ", expectedResponse=" + this.b + ", expectedResponseData=" + this.c + ", explanations=" + this.d + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeParcelable(this.a, i);
        dest.writeParcelable(this.b, i);
        dest.writeParcelable(this.c, i);
        LinkedHashMap linkedHashMap = this.d;
        if (linkedHashMap == null) {
            dest.writeInt(0);
            return;
        }
        dest.writeInt(1);
        dest.writeInt(linkedHashMap.size());
        for (Map.Entry entry : linkedHashMap.entrySet()) {
            dest.writeInt(((Number) entry.getKey()).intValue());
            dest.writeParcelable((Parcelable) entry.getValue(), i);
        }
    }
}
