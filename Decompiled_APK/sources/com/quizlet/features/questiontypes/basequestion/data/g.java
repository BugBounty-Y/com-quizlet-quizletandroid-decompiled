package com.quizlet.features.questiontypes.basequestion.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.features.questiontypes.basequestion.data.ShowQuestion;
import com.quizlet.generated.enums.A1;
import com.quizlet.studiablemodels.TrueFalseStudiableQuestion;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        return new ShowQuestion.TrueFalse((TrueFalseStudiableQuestion) parcel.readParcelable(ShowQuestion.TrueFalse.class.getClassLoader()), parcel.readLong(), parcel.readLong(), (QuestionSettings) parcel.readParcelable(ShowQuestion.TrueFalse.class.getClassLoader()), A1.valueOf(parcel.readString()), parcel.readInt() != 0);
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new ShowQuestion.TrueFalse[i];
    }
}
