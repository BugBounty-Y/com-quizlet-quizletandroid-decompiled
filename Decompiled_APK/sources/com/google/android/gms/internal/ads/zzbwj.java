package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.Arrays;
import org.json.JSONArray;

/* loaded from: classes2.dex */
public final class zzbwj extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzbwj> CREATOR = new C2128h6(16);
    public final String a;
    public final int b;

    public zzbwj(String str, int i) {
        this.a = str;
        this.b = i;
    }

    public static zzbwj a(JSONArray jSONArray) {
        if (jSONArray == null || jSONArray.length() == 0) {
            return null;
        }
        return new zzbwj(jSONArray.getJSONObject(0).optString("rb_type"), jSONArray.getJSONObject(0).optInt("rb_amount"));
    }

    public final boolean equals(Object obj) {
        if (obj != null && (obj instanceof zzbwj)) {
            zzbwj zzbwjVar = (zzbwj) obj;
            if (com.google.android.gms.common.internal.u.l(this.a, zzbwjVar.a) && com.google.android.gms.common.internal.u.l(Integer.valueOf(this.b), Integer.valueOf(zzbwjVar.b))) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, Integer.valueOf(this.b)});
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 2, this.a);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.b);
        AbstractC3489l3.o(iN, parcel);
    }
}
