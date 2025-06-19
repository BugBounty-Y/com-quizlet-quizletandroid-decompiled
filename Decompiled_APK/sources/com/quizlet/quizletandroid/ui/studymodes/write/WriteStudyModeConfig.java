package com.quizlet.quizletandroid.ui.studymodes.write;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.generated.enums.O1;

/* loaded from: classes3.dex */
public class WriteStudyModeConfig implements Parcelable {
    public static final Parcelable.Creator<WriteStudyModeConfig> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(17);
    public O1 a;
    public boolean b;
    public boolean c;
    public boolean d;
    public boolean e;

    public WriteStudyModeConfig(O1 o1, boolean z, boolean z2, boolean z3, boolean z4) {
        this.a = o1;
        this.b = z;
        this.c = z2;
        this.d = z3;
        this.e = z4;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        parcel.writeInt(this.a.a());
        parcel.writeByte(this.b ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.c ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.d ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.e ? (byte) 1 : (byte) 0);
    }
}
