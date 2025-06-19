package com.quizlet.quizletandroid.ui.common.widgets;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.quizletandroid.ui.common.widgets.EditTextDatePicker;

/* loaded from: classes3.dex */
public final class b implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        return new EditTextDatePicker.SavedState(parcel);
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new EditTextDatePicker.SavedState[i];
    }
}
