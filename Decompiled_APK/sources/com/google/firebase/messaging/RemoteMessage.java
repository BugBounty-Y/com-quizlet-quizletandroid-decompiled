package com.google.firebase.messaging;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import androidx.collection.C0208f;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.Map;

/* loaded from: classes2.dex */
public final class RemoteMessage extends AbstractSafeParcelable {
    public static final Parcelable.Creator<RemoteMessage> CREATOR = new com.google.android.gms.fido.fido2.api.common.i(24);
    public final Bundle a;
    public C0208f b;
    public androidx.work.impl.model.c c;

    public RemoteMessage(Bundle bundle) {
        this.a = bundle;
    }

    public final Map a() {
        if (this.b == null) {
            C0208f c0208f = new C0208f(0);
            Bundle bundle = this.a;
            for (String str : bundle.keySet()) {
                Object obj = bundle.get(str);
                if (obj instanceof String) {
                    String str2 = (String) obj;
                    if (!str.startsWith("google.") && !str.startsWith("gcm.") && !str.equals("from") && !str.equals("message_type") && !str.equals("collapse_key")) {
                        c0208f.put(str, str2);
                    }
                }
            }
            this.b = c0208f;
        }
        return this.b;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.c(parcel, 2, this.a);
        AbstractC3489l3.o(iN, parcel);
    }
}
