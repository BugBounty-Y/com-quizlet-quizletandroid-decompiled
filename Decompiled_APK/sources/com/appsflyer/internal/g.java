package com.appsflyer.internal;

import android.content.Context;
import android.hardware.SensorEvent;

/* loaded from: classes.dex */
public final /* synthetic */ class g implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ g(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                AFb1lSDK.getCurrencyIso4217Code((AFb1lSDK) this.b, (AFh1qSDK) this.c);
                break;
            case 1:
                ((AFj1pSDK) this.b).G_((SensorEvent) this.c);
                break;
            case 2:
                AFj1uSDK.getMonetizationNetwork((AFj1uSDK) this.b, (Context) this.c);
                break;
            case 3:
                ((AFj1vSDK) this.b).getCurrencyIso4217Code((Context) this.c);
                break;
            default:
                AFj1zSDK.getMonetizationNetwork((AFj1zSDK) this.b, (Context) this.c);
                break;
        }
    }
}
