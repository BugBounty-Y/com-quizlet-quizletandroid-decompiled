package com.quizlet.features.questionnaire.navigation;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.features.questionnaire.navigation.Control;
import com.quizlet.features.questionnaire.navigation.StepModel;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class s implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        String string = parcel.readString();
        Progress progressCreateFromParcel = Progress.CREATOR.createFromParcel(parcel);
        int i = parcel.readInt();
        ArrayList arrayList = new ArrayList(i);
        for (int i2 = 0; i2 != i; i2++) {
            arrayList.add(Control.Button.CREATOR.createFromParcel(parcel));
        }
        return new StepModel.Intro(string, progressCreateFromParcel, arrayList, Control.Button.CREATOR.createFromParcel(parcel), parcel.readString(), parcel.readString());
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new StepModel.Intro[i];
    }
}
