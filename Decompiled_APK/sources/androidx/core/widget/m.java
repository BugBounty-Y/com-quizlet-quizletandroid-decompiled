package androidx.core.widget;

import android.os.Parcel;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class m {
    public final byte[] a;
    public final String b;
    public final long c;

    public m(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        byte[] bArr = new byte[parcel.readInt()];
        this.a = bArr;
        parcel.readByteArray(bArr);
        String string = parcel.readString();
        Intrinsics.d(string);
        this.b = string;
        this.c = parcel.readLong();
    }
}
