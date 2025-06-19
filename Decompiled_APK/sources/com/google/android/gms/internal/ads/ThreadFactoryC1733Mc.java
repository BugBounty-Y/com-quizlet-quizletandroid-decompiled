package com.google.android.gms.internal.ads;

import java.io.Serializable;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/* renamed from: com.google.android.gms.internal.ads.Mc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class ThreadFactoryC1733Mc implements ThreadFactory {
    public final /* synthetic */ int a;
    public final Serializable b;

    public /* synthetic */ ThreadFactoryC1733Mc(String str) {
        this.a = 2;
        this.b = str;
    }

    @Override // java.util.concurrent.ThreadFactory
    public final Thread newThread(Runnable runnable) {
        Serializable serializable = this.b;
        switch (this.a) {
            case 0:
                return new Thread(runnable, android.support.v4.media.session.a.f(((AtomicInteger) serializable).getAndIncrement(), "AdWorker(SCION_TASK_EXECUTOR) #"));
            case 1:
                return new Thread(runnable, android.support.v4.media.session.a.f(((AtomicInteger) serializable).getAndIncrement(), "AdWorker(NG) #"));
            default:
                String str = Yo.a;
                return new Thread(runnable, (String) serializable);
        }
    }

    public ThreadFactoryC1733Mc(int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = new AtomicInteger(1);
                break;
            default:
                this.b = new AtomicInteger(1);
                break;
        }
    }
}
