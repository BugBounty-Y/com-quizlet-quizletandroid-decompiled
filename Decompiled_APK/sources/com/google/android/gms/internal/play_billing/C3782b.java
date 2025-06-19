package com.google.android.gms.internal.play_billing;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.comscore.streaming.ContentDistributionModel;
import com.google.android.gms.internal.ads.AbstractC2771w5;

/* renamed from: com.google.android.gms.internal.play_billing.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3782b extends AbstractC2771w5 implements InterfaceC3788d {
    public final int h4(int i, Bundle bundle, String str, String str2) {
        Parcel parcelF4 = f4();
        parcelF4.writeInt(i);
        parcelF4.writeString(str);
        parcelF4.writeString(str2);
        int i2 = AbstractC3791e.a;
        parcelF4.writeInt(1);
        bundle.writeToParcel(parcelF4, 0);
        Parcel parcelG4 = g4(10, parcelF4);
        int i3 = parcelG4.readInt();
        parcelG4.recycle();
        return i3;
    }

    public final Bundle i4(String str, String str2, Bundle bundle) {
        Parcel parcelF4 = f4();
        parcelF4.writeInt(9);
        parcelF4.writeString(str);
        parcelF4.writeString(str2);
        int i = AbstractC3791e.a;
        parcelF4.writeInt(1);
        bundle.writeToParcel(parcelF4, 0);
        Parcel parcelG4 = g4(ContentDistributionModel.EXCLUSIVELY_ONLINE, parcelF4);
        Parcelable.Creator creator = Bundle.CREATOR;
        Bundle bundle2 = (Bundle) AbstractC3791e.a(parcelG4);
        parcelG4.recycle();
        return bundle2;
    }

    public final Bundle j4(String str, String str2, String str3) {
        Parcel parcelF4 = f4();
        parcelF4.writeInt(3);
        parcelF4.writeString(str);
        parcelF4.writeString(str2);
        parcelF4.writeString(str3);
        parcelF4.writeString(null);
        Parcel parcelG4 = g4(3, parcelF4);
        Parcelable.Creator creator = Bundle.CREATOR;
        Bundle bundle = (Bundle) AbstractC3791e.a(parcelG4);
        parcelG4.recycle();
        return bundle;
    }

    public final Bundle k4(int i, String str, String str2, String str3, Bundle bundle) {
        Parcel parcelF4 = f4();
        parcelF4.writeInt(i);
        parcelF4.writeString(str);
        parcelF4.writeString(str2);
        parcelF4.writeString(str3);
        parcelF4.writeString(null);
        int i2 = AbstractC3791e.a;
        parcelF4.writeInt(1);
        bundle.writeToParcel(parcelF4, 0);
        Parcel parcelG4 = g4(8, parcelF4);
        Parcelable.Creator creator = Bundle.CREATOR;
        Bundle bundle2 = (Bundle) AbstractC3791e.a(parcelG4);
        parcelG4.recycle();
        return bundle2;
    }

    public final Bundle l4(String str, String str2, String str3) {
        Parcel parcelF4 = f4();
        parcelF4.writeInt(3);
        parcelF4.writeString(str);
        parcelF4.writeString(str2);
        parcelF4.writeString(str3);
        Parcel parcelG4 = g4(4, parcelF4);
        Parcelable.Creator creator = Bundle.CREATOR;
        Bundle bundle = (Bundle) AbstractC3791e.a(parcelG4);
        parcelG4.recycle();
        return bundle;
    }

    public final Bundle m4(int i, String str, String str2, String str3, Bundle bundle) {
        Parcel parcelF4 = f4();
        parcelF4.writeInt(i);
        parcelF4.writeString(str);
        parcelF4.writeString(str2);
        parcelF4.writeString(str3);
        int i2 = AbstractC3791e.a;
        parcelF4.writeInt(1);
        bundle.writeToParcel(parcelF4, 0);
        Parcel parcelG4 = g4(11, parcelF4);
        Parcelable.Creator creator = Bundle.CREATOR;
        Bundle bundle2 = (Bundle) AbstractC3791e.a(parcelG4);
        parcelG4.recycle();
        return bundle2;
    }

    public final Bundle n4(int i, String str, String str2, Bundle bundle, Bundle bundle2) {
        Parcel parcelF4 = f4();
        parcelF4.writeInt(i);
        parcelF4.writeString(str);
        parcelF4.writeString(str2);
        int i2 = AbstractC3791e.a;
        parcelF4.writeInt(1);
        bundle.writeToParcel(parcelF4, 0);
        parcelF4.writeInt(1);
        bundle2.writeToParcel(parcelF4, 0);
        Parcel parcelG4 = g4(ContentDistributionModel.TV_AND_ONLINE, parcelF4);
        Parcelable.Creator creator = Bundle.CREATOR;
        Bundle bundle3 = (Bundle) AbstractC3791e.a(parcelG4);
        parcelG4.recycle();
        return bundle3;
    }
}
