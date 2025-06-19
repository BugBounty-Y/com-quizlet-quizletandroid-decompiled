package com.google.firebase.concurrent;

import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements f {
    public final /* synthetic */ int a;
    public final /* synthetic */ e b;
    public final /* synthetic */ Runnable c;
    public final /* synthetic */ long d;
    public final /* synthetic */ long e;
    public final /* synthetic */ TimeUnit f;

    public /* synthetic */ c(e eVar, Runnable runnable, long j, long j2, TimeUnit timeUnit, int i) {
        this.a = i;
        this.b = eVar;
        this.c = runnable;
        this.d = j;
        this.e = j2;
        this.f = timeUnit;
    }

    @Override // com.google.firebase.concurrent.f
    public final ScheduledFuture b(com.quizlet.data.repository.school.membership.a aVar) {
        switch (this.a) {
            case 0:
                e eVar = this.b;
                return eVar.b.scheduleAtFixedRate(new d(eVar, this.c, aVar, 0), this.d, this.e, this.f);
            default:
                e eVar2 = this.b;
                return eVar2.b.scheduleWithFixedDelay(new d(eVar2, this.c, aVar, 2), this.d, this.e, this.f);
        }
    }
}
