package com.quizlet.uicommon.ui.common.dialogs;

import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import com.quizlet.uicommon.ui.common.dialogs.QAlertDialogFragment;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        return new QAlertDialogFragment.DialogData(parcel.readString(), parcel.readString(), parcel.readString(), parcel.readString(), parcel.readInt() != 0, (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(parcel));
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new QAlertDialogFragment.DialogData[i];
    }
}
