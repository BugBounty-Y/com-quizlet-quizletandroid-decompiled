package com.google.android.gms.ads.formats;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class AdManagerAdViewOptions extends AbstractSafeParcelable {

    @NonNull
    public static final Parcelable.Creator<AdManagerAdViewOptions> CREATOR = new android.support.v4.media.a(23);
    public final boolean a;

    public AdManagerAdViewOptions(com.quizlet.shared.usecase.folderstudymaterials.d dVar) {
        dVar.getClass();
        this.a = false;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.a ? 1 : 0);
        AbstractC3489l3.o(iN, parcel);
    }

    public AdManagerAdViewOptions(boolean z) {
        this.a = z;
    }
}
