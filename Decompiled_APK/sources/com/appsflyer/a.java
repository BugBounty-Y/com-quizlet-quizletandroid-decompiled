package com.appsflyer;

import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;

    public /* synthetic */ a(int i, Function1 function1) {
        this.a = i;
        this.b = function1;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                AFLogger.getMediationNetwork(this.b);
                break;
            case 1:
                this.b.invoke(Boolean.FALSE);
                break;
            default:
                this.b.invoke(Boolean.TRUE);
                break;
        }
    }
}
