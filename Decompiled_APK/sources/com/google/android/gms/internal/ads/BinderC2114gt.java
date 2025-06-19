package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.Parcel;

/* renamed from: com.google.android.gms.internal.ads.gt, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC2114gt extends AbstractBinderC2814x5 {
    public final androidx.webkit.internal.p a;
    public final /* synthetic */ C2158ht b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BinderC2114gt(C2158ht c2158ht, androidx.webkit.internal.p pVar) {
        super("com.google.android.play.core.lmd.protocol.ILmdOverlayServiceListener");
        this.b = c2158ht;
        this.a = pVar;
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        Tm tm;
        if (i != 1) {
            return false;
        }
        Bundle bundle = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
        AbstractC2857y5.b(parcel);
        int i2 = bundle.getInt("statusCode", 8150);
        String string = bundle.getString("sessionToken");
        if (string == null) {
            string = null;
        }
        this.a.x(new C1939ct(i2, string));
        if (i2 == 8157 && (tm = this.b.a) != null) {
            C2158ht.c.c("unbind LMD display overlay service", new Object[0]);
            tm.c(new RunnableC2104gj(tm, 20));
        }
        return true;
    }
}
