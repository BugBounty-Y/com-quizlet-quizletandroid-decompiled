package com.google.android.gms.common.moduleinstall.internal;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import com.google.android.gms.ads.internal.f;
import com.google.android.gms.common.api.i;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;

/* loaded from: classes2.dex */
public class ApiFeatureRequest extends AbstractSafeParcelable {

    @NonNull
    public static final Parcelable.Creator<ApiFeatureRequest> CREATOR = new f(25);
    public final ArrayList a;
    public final boolean b;
    public final String c;
    public final String d;

    public ApiFeatureRequest(ArrayList arrayList, boolean z, String str, String str2) {
        u.h(arrayList);
        this.a = arrayList;
        this.b = z;
        this.c = str;
        this.d = str2;
    }

    public static ApiFeatureRequest a(List list, boolean z) {
        TreeSet treeSet = new TreeSet(androidx.constraintlayout.core.e.c);
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            Collections.addAll(treeSet, ((i) it2.next()).a());
        }
        return new ApiFeatureRequest(new ArrayList(treeSet), z, null, null);
    }

    public final boolean equals(Object obj) {
        if (obj == null || !(obj instanceof ApiFeatureRequest)) {
            return false;
        }
        ApiFeatureRequest apiFeatureRequest = (ApiFeatureRequest) obj;
        return this.b == apiFeatureRequest.b && u.l(this.a, apiFeatureRequest.a) && u.l(this.c, apiFeatureRequest.c) && u.l(this.d, apiFeatureRequest.d);
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{Boolean.valueOf(this.b), this.a, this.c, this.d});
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.l(parcel, 1, this.a);
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(this.b ? 1 : 0);
        AbstractC3489l3.h(parcel, 3, this.c);
        AbstractC3489l3.h(parcel, 4, this.d);
        AbstractC3489l3.o(iN, parcel);
    }
}
