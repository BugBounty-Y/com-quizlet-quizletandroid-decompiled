package com.google.android.gms.common;

import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.common.internal.H;
import com.google.android.gms.common.internal.u;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;

/* loaded from: classes2.dex */
public abstract class k extends com.google.android.gms.internal.p000authapi.g implements H {
    public static final /* synthetic */ int c = 0;
    public final int b;

    public k(byte[] bArr) {
        super("com.google.android.gms.common.internal.ICertData", 2);
        u.b(bArr.length == 25);
        this.b = Arrays.hashCode(bArr);
    }

    public static byte[] I3(String str) {
        try {
            return str.getBytes("ISO-8859-1");
        } catch (UnsupportedEncodingException e) {
            throw new AssertionError(e);
        }
    }

    public final boolean equals(Object obj) {
        com.google.android.gms.dynamic.a aVarJ;
        if (obj != null && (obj instanceof H)) {
            try {
                H h = (H) obj;
                if (h.zze() == this.b && (aVarJ = h.j()) != null) {
                    return Arrays.equals(v3(), (byte[]) com.google.android.gms.dynamic.b.I3(aVarJ));
                }
            } catch (RemoteException e) {
                Log.e("GoogleCertificates", "Failed to get Google certificates from remote", e);
            }
        }
        return false;
    }

    public final int hashCode() {
        return this.b;
    }

    @Override // com.google.android.gms.common.internal.H
    public final com.google.android.gms.dynamic.a j() {
        return new com.google.android.gms.dynamic.b(v3());
    }

    @Override // com.google.android.gms.internal.p000authapi.g
    public final boolean p3(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            com.google.android.gms.dynamic.a aVarJ = j();
            parcel2.writeNoException();
            com.google.android.gms.internal.common.h.b(parcel2, aVarJ);
            return true;
        }
        if (i != 2) {
            return false;
        }
        parcel2.writeNoException();
        parcel2.writeInt(this.b);
        return true;
    }

    public abstract byte[] v3();

    @Override // com.google.android.gms.common.internal.H
    public final int zze() {
        return this.b;
    }
}
