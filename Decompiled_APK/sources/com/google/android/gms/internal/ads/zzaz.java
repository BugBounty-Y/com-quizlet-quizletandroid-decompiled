package com.google.android.gms.internal.ads;

import java.io.IOException;

/* loaded from: classes2.dex */
public class zzaz extends IOException {
    public final boolean a;
    public final int b;

    public zzaz(String str, RuntimeException runtimeException, boolean z, int i) {
        super(str, runtimeException);
        this.a = z;
        this.b = i;
    }

    public static zzaz a(RuntimeException runtimeException, String str) {
        return new zzaz(str, runtimeException, true, 1);
    }

    public static zzaz b(String str) {
        return new zzaz(str, null, false, 1);
    }

    @Override // java.lang.Throwable
    public final String getMessage() {
        String message = super.getMessage();
        StringBuilder sbX = android.support.v4.media.session.a.x(message != null ? message.concat(" ") : "", "{contentIsMalformed=");
        sbX.append(this.a);
        sbX.append(", dataType=");
        return android.support.v4.media.session.a.r(sbX, this.b, "}");
    }
}
