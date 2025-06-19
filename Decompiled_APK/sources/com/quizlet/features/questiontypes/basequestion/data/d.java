package com.quizlet.features.questiontypes.basequestion.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.features.questiontypes.basequestion.data.ShowQuestion;
import com.quizlet.generated.enums.A1;
import com.quizlet.studiablemodels.MultipleChoiceStudiableQuestion;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        boolean z;
        boolean z2;
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        MultipleChoiceStudiableQuestion multipleChoiceStudiableQuestion = (MultipleChoiceStudiableQuestion) parcel.readParcelable(ShowQuestion.MultipleChoice.class.getClassLoader());
        long j = parcel.readLong();
        long j2 = parcel.readLong();
        QuestionSettings questionSettings = (QuestionSettings) parcel.readParcelable(ShowQuestion.MultipleChoice.class.getClassLoader());
        A1 a1ValueOf = A1.valueOf(parcel.readString());
        boolean z3 = false;
        boolean z4 = true;
        if (parcel.readInt() != 0) {
            z = false;
            z3 = true;
        } else {
            z = false;
        }
        if (parcel.readInt() != 0) {
            z2 = true;
        } else {
            z2 = true;
            z4 = z;
        }
        if (parcel.readInt() == 0) {
            z2 = z;
        }
        return new ShowQuestion.MultipleChoice(multipleChoiceStudiableQuestion, j, j2, questionSettings, a1ValueOf, z3, z4, z2);
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new ShowQuestion.MultipleChoice[i];
    }
}
