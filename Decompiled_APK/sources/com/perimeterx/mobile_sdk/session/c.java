package com.perimeterx.mobile_sdk.session;

import com.perimeterx.mobile_sdk.PerimeterXDelegate;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ PerimeterXDelegate b;
    public final /* synthetic */ String c;

    public /* synthetic */ c(PerimeterXDelegate perimeterXDelegate, String str, int i) {
        this.a = i;
        this.b = perimeterXDelegate;
        this.c = str;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                PerimeterXDelegate perimeterXDelegate = this.b;
                if (perimeterXDelegate != null) {
                    perimeterXDelegate.perimeterxChallengeCancelledHandler(this.c);
                    break;
                }
                break;
            default:
                PerimeterXDelegate perimeterXDelegate2 = this.b;
                if (perimeterXDelegate2 != null) {
                    perimeterXDelegate2.perimeterxChallengeSolvedHandler(this.c);
                    break;
                }
                break;
        }
    }
}
