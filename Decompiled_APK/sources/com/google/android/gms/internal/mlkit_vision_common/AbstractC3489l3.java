package com.google.android.gms.internal.mlkit_vision_common;

import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.l3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3489l3 {
    public static List a() {
        return kotlin.collections.A.b(com.google.android.gms.internal.mlkit_vision_camera.D1.b("authToken", new com.quizlet.features.practicetest.navigation.a(26)));
    }

    public static String b(com.quizlet.features.settings.composables.navigation.i iVar, String reAuthToken) {
        Intrinsics.checkNotNullParameter(reAuthToken, "reAuthToken");
        return kotlin.text.D.o(iVar.e(), "{authToken}", reAuthToken, false);
    }

    public static void c(Parcel parcel, int i, Bundle bundle) {
        if (bundle == null) {
            return;
        }
        int iN = n(i, parcel);
        parcel.writeBundle(bundle);
        o(iN, parcel);
    }

    public static void d(Parcel parcel, int i, byte[] bArr) {
        if (bArr == null) {
            return;
        }
        int iN = n(i, parcel);
        parcel.writeByteArray(bArr);
        o(iN, parcel);
    }

    public static void e(Parcel parcel, int i, IBinder iBinder) {
        if (iBinder == null) {
            return;
        }
        int iN = n(i, parcel);
        parcel.writeStrongBinder(iBinder);
        o(iN, parcel);
    }

    public static void f(Parcel parcel, int i, ArrayList arrayList) {
        if (arrayList == null) {
            return;
        }
        int iN = n(i, parcel);
        int size = arrayList.size();
        parcel.writeInt(size);
        for (int i2 = 0; i2 < size; i2++) {
            parcel.writeInt(((Integer) arrayList.get(i2)).intValue());
        }
        o(iN, parcel);
    }

    public static void g(Parcel parcel, int i, Parcelable parcelable, int i2) {
        if (parcelable == null) {
            return;
        }
        int iN = n(i, parcel);
        parcelable.writeToParcel(parcel, i2);
        o(iN, parcel);
    }

    public static void h(Parcel parcel, int i, String str) {
        if (str == null) {
            return;
        }
        int iN = n(i, parcel);
        parcel.writeString(str);
        o(iN, parcel);
    }

    public static void i(Parcel parcel, int i, String[] strArr) {
        if (strArr == null) {
            return;
        }
        int iN = n(i, parcel);
        parcel.writeStringArray(strArr);
        o(iN, parcel);
    }

    public static void j(Parcel parcel, int i, List list) {
        if (list == null) {
            return;
        }
        int iN = n(i, parcel);
        parcel.writeStringList(list);
        o(iN, parcel);
    }

    public static void k(Parcel parcel, int i, Parcelable[] parcelableArr, int i2) {
        if (parcelableArr == null) {
            return;
        }
        int iN = n(i, parcel);
        parcel.writeInt(parcelableArr.length);
        for (Parcelable parcelable : parcelableArr) {
            if (parcelable == null) {
                parcel.writeInt(0);
            } else {
                int iDataPosition = parcel.dataPosition();
                parcel.writeInt(1);
                int iDataPosition2 = parcel.dataPosition();
                parcelable.writeToParcel(parcel, i2);
                int iDataPosition3 = parcel.dataPosition();
                parcel.setDataPosition(iDataPosition);
                parcel.writeInt(iDataPosition3 - iDataPosition2);
                parcel.setDataPosition(iDataPosition3);
            }
        }
        o(iN, parcel);
    }

    public static void l(Parcel parcel, int i, List list) {
        if (list == null) {
            return;
        }
        int iN = n(i, parcel);
        int size = list.size();
        parcel.writeInt(size);
        for (int i2 = 0; i2 < size; i2++) {
            Parcelable parcelable = (Parcelable) list.get(i2);
            if (parcelable == null) {
                parcel.writeInt(0);
            } else {
                int iDataPosition = parcel.dataPosition();
                parcel.writeInt(1);
                int iDataPosition2 = parcel.dataPosition();
                parcelable.writeToParcel(parcel, 0);
                int iDataPosition3 = parcel.dataPosition();
                parcel.setDataPosition(iDataPosition);
                parcel.writeInt(iDataPosition3 - iDataPosition2);
                parcel.setDataPosition(iDataPosition3);
            }
        }
        o(iN, parcel);
    }

    public static void m(Parcel parcel, int i, int i2) {
        parcel.writeInt(i | (i2 << 16));
    }

    public static int n(int i, Parcel parcel) {
        parcel.writeInt(i | (-65536));
        parcel.writeInt(0);
        return parcel.dataPosition();
    }

    public static void o(int i, Parcel parcel) {
        int iDataPosition = parcel.dataPosition();
        parcel.setDataPosition(i - 4);
        parcel.writeInt(iDataPosition - i);
        parcel.setDataPosition(iDataPosition);
    }
}
