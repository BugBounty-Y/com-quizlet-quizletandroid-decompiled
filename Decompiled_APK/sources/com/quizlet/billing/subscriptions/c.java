package com.quizlet.billing.subscriptions;

import kotlin.jvm.internal.Intrinsics;
import retrofit2.HttpException;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;

    public /* synthetic */ c(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                break;
            case 1:
                timber.log.c.b((Throwable) obj);
                break;
            case 2:
                timber.log.c.a((Throwable) obj);
                break;
            case 3:
                timber.log.c.a((Throwable) obj);
                break;
            case 4:
                Throwable it2 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                timber.log.c.a.e(it2);
                break;
            case 5:
                timber.log.c.a.h((Throwable) obj);
                break;
            default:
                Throwable th = (Throwable) obj;
                if (th instanceof HttpException) {
                    timber.log.c.a.h(th);
                    break;
                }
                break;
        }
    }
}
