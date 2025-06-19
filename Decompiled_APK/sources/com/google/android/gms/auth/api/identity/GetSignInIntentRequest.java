package com.google.android.gms.auth.api.identity;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.Arrays;

@Deprecated
/* loaded from: classes2.dex */
public class GetSignInIntentRequest extends AbstractSafeParcelable {

    @NonNull
    public static final Parcelable.Creator<GetSignInIntentRequest> CREATOR = new com.google.android.gms.ads.internal.f(4);
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final boolean e;
    public final int f;

    public GetSignInIntentRequest(int i, String str, String str2, String str3, String str4, boolean z) {
        u.h(str);
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = str4;
        this.e = z;
        this.f = i;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof GetSignInIntentRequest)) {
            return false;
        }
        GetSignInIntentRequest getSignInIntentRequest = (GetSignInIntentRequest) obj;
        return u.l(this.a, getSignInIntentRequest.a) && u.l(this.d, getSignInIntentRequest.d) && u.l(this.b, getSignInIntentRequest.b) && u.l(Boolean.valueOf(this.e), Boolean.valueOf(getSignInIntentRequest.e)) && this.f == getSignInIntentRequest.f;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, this.b, this.d, Boolean.valueOf(this.e), Integer.valueOf(this.f)});
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 1, this.a);
        AbstractC3489l3.h(parcel, 2, this.b);
        AbstractC3489l3.h(parcel, 3, this.c);
        AbstractC3489l3.h(parcel, 4, this.d);
        AbstractC3489l3.m(parcel, 5, 4);
        parcel.writeInt(this.e ? 1 : 0);
        AbstractC3489l3.m(parcel, 6, 4);
        parcel.writeInt(this.f);
        AbstractC3489l3.o(iN, parcel);
    }
}
