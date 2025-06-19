package com.google.android.gms.internal.ads;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;

/* loaded from: classes2.dex */
public class zzgx extends zzgh {
    public final int b;

    public zzgx() {
        this.b = 1;
    }

    public static zzgx a(int i, IOException iOException) {
        String message = iOException.getMessage();
        int i2 = iOException instanceof SocketTimeoutException ? com.pubmatic.sdk.common.h.AD_NOT_READY : iOException instanceof InterruptedIOException ? 1004 : (message == null || !AbstractC2543qs.f(message).matches("cleartext.*not permitted.*")) ? 2001 : 2007;
        return i2 == 2007 ? new zzgw("Cleartext HTTP traffic not permitted. See https://developer.android.com/guide/topics/media/issues/cleartext-not-permitted", iOException, 2007, 1) : new zzgx(iOException, i2, i);
    }

    public zzgx(IOException iOException, int i, int i2) {
        super(i == 2000 ? i2 != 1 ? 2000 : com.pubmatic.sdk.common.h.AD_ALREADY_SHOWN : i, iOException);
        this.b = i2;
    }

    public zzgx(String str, int i, int i2) {
        super(str, i == 2000 ? i2 != 1 ? 2000 : com.pubmatic.sdk.common.h.AD_ALREADY_SHOWN : i);
        this.b = i2;
    }

    public zzgx(String str, IOException iOException, int i, int i2) {
        super(str, iOException, i == 2000 ? i2 != 1 ? 2000 : com.pubmatic.sdk.common.h.AD_ALREADY_SHOWN : i);
        this.b = i2;
    }
}
