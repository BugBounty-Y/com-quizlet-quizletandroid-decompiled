package com.quizlet.features.questionnaire.navigation;

import android.os.Parcel;
import android.os.Parcelable;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class QuestionnaireModel implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<QuestionnaireModel> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(9);
    public final String a;
    public final LinkedHashMap b;

    public QuestionnaireModel(String startStep, LinkedHashMap steps) {
        Intrinsics.checkNotNullParameter(startStep, "startStep");
        Intrinsics.checkNotNullParameter(steps, "steps");
        this.a = startStep;
        this.b = steps;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof QuestionnaireModel)) {
            return false;
        }
        QuestionnaireModel questionnaireModel = (QuestionnaireModel) obj;
        return Intrinsics.b(this.a, questionnaireModel.a) && this.b.equals(questionnaireModel.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "QuestionnaireModel(startStep=" + this.a + ", steps=" + this.b + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a);
        LinkedHashMap linkedHashMap = this.b;
        dest.writeInt(linkedHashMap.size());
        for (Map.Entry entry : linkedHashMap.entrySet()) {
            dest.writeString((String) entry.getKey());
            dest.writeParcelable((Parcelable) entry.getValue(), i);
        }
    }
}
