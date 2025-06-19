package com.google.android.gms.common.api.internal;

import com.google.android.gms.common.api.Status;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class F implements com.google.android.gms.common.api.j {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ BasePendingResult b;
    public final /* synthetic */ Object c;

    public F(BasePendingResult basePendingResult, com.google.android.gms.tasks.f fVar, com.onetrust.otpublishers.headless.Internal.Helper.h hVar) {
        this.b = basePendingResult;
        this.c = fVar;
    }

    @Override // com.google.android.gms.common.api.j
    public final void a(Status status) {
        switch (this.a) {
            case 0:
                ((Map) ((com.quizlet.data.repository.explanations.myexplanations.a) this.c).b).remove(this.b);
                break;
            default:
                boolean zA = status.a();
                com.google.android.gms.tasks.f fVar = (com.google.android.gms.tasks.f) this.c;
                if (!zA) {
                    fVar.a(com.google.android.gms.common.internal.u.m(status));
                    break;
                } else {
                    this.b.await(0L, TimeUnit.MILLISECONDS);
                    fVar.b(null);
                    break;
                }
        }
    }

    public F(com.quizlet.data.repository.explanations.myexplanations.a aVar, BasePendingResult basePendingResult) {
        this.b = basePendingResult;
        this.c = aVar;
    }
}
