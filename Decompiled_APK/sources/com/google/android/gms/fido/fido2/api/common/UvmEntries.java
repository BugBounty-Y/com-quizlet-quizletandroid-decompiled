package com.google.android.gms.fido.fido2.api.common;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import org.json.JSONArray;
import org.json.JSONException;

/* loaded from: classes2.dex */
public class UvmEntries extends AbstractSafeParcelable {

    @NonNull
    public static final Parcelable.Creator<UvmEntries> CREATOR = new com.google.android.gms.common.i(22);
    public final ArrayList a;

    public UvmEntries(ArrayList arrayList) {
        this.a = arrayList;
    }

    public final JSONArray a() throws JSONException {
        try {
            JSONArray jSONArray = new JSONArray();
            ArrayList arrayList = this.a;
            if (arrayList != null) {
                for (int i = 0; i < arrayList.size(); i++) {
                    UvmEntry uvmEntry = (UvmEntry) arrayList.get(i);
                    JSONArray jSONArray2 = new JSONArray();
                    jSONArray2.put((int) uvmEntry.c);
                    jSONArray2.put((int) uvmEntry.b);
                    jSONArray2.put((int) uvmEntry.c);
                    jSONArray.put(i, jSONArray2);
                }
            }
            return jSONArray;
        } catch (JSONException e) {
            throw new RuntimeException("Error encoding UvmEntries to JSON object", e);
        }
    }

    public final boolean equals(Object obj) {
        ArrayList arrayList;
        if (!(obj instanceof UvmEntries)) {
            return false;
        }
        UvmEntries uvmEntries = (UvmEntries) obj;
        ArrayList arrayList2 = this.a;
        if (arrayList2 == null && uvmEntries.a == null) {
            return true;
        }
        return arrayList2 != null && (arrayList = uvmEntries.a) != null && arrayList2.containsAll(arrayList) && uvmEntries.a.containsAll(arrayList2);
    }

    public final int hashCode() {
        ArrayList arrayList = this.a;
        return Arrays.hashCode(new Object[]{arrayList == null ? null : new HashSet(arrayList)});
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.l(parcel, 1, this.a);
        AbstractC3489l3.o(iN, parcel);
    }
}
