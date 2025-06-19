package com.quizlet.infra.legacysyncengine.managers;

import com.quizlet.db.data.caches.UserInfoCacheKt;
import com.quizlet.db.data.models.persisted.DBUser;
import java.io.IOException;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ d b;

    public /* synthetic */ c(d dVar, int i) {
        this.a = i;
        this.b = dVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                this.b.d((DBUser) obj);
                break;
            case 1:
                d dVar = this.b;
                UserInfoCacheKt.a(dVar.e, null);
                dVar.f.b(null);
                break;
            default:
                Throwable th = (Throwable) obj;
                d dVar2 = this.b;
                dVar2.getClass();
                if (th instanceof IOException) {
                    timber.log.c.a.i(th, "Error while hitting logout endpoint", new Object[0]);
                } else {
                    timber.log.c.a.f(th, "Error while hitting logout endpoint", new Object[0]);
                }
                UserInfoCacheKt.a(dVar2.e, null);
                dVar2.f.b(null);
                break;
        }
    }
}
