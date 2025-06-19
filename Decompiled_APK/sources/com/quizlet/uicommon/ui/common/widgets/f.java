package com.quizlet.uicommon.ui.common.widgets;

import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel source) {
        Intrinsics.checkNotNullParameter(source, "parcel");
        Intrinsics.checkNotNullParameter(source, "source");
        QFormField.SavedState savedState = new QFormField.SavedState(source);
        savedState.a = source.readInt();
        Parcelable.Creator creator = TextUtils.CHAR_SEQUENCE_CREATOR;
        savedState.b = (CharSequence) creator.createFromParcel(source);
        savedState.c = (CharSequence) creator.createFromParcel(source);
        savedState.d = source.readSparseArray(QFormField.SavedState.class.getClassLoader());
        return savedState;
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new QFormField.SavedState[i];
    }
}
