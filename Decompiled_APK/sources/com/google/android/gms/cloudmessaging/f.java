package com.google.android.gms.cloudmessaging;

import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final /* synthetic */ class f implements Executor {
    public static final /* synthetic */ f b = new f(0);
    public static final /* synthetic */ f c = new f(1);
    public final /* synthetic */ int a;

    public /* synthetic */ f(int i) {
        this.a = i;
    }

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable runnable) {
        switch (this.a) {
            case 0:
                runnable.run();
                break;
            default:
                runnable.run();
                break;
        }
    }
}
