package com.onetrust.otpublishers.headless.Internal.Network;

import com.onetrust.otpublishers.headless.Public.OTCallback;
import com.onetrust.otpublishers.headless.Public.Response.OTResponse;

/* loaded from: classes2.dex */
public final /* synthetic */ class b implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ OTCallback b;
    public final /* synthetic */ OTResponse c;

    public /* synthetic */ b(OTCallback oTCallback, OTResponse oTResponse, int i) {
        this.a = i;
        this.b = oTCallback;
        this.c = oTResponse;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.onSuccess(this.c);
                break;
            default:
                this.b.onSuccess(this.c);
                break;
        }
    }
}
