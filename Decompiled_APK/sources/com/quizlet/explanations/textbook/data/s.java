package com.quizlet.explanations.textbook.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.explanations.textbook.data.TextbookSetUpState;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class s implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        return new TextbookSetUpState.TableOfContents(parcel.readString());
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new TextbookSetUpState.TableOfContents[i];
    }
}
