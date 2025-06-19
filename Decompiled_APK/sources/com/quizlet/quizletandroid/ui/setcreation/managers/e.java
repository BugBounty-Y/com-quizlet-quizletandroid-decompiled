package com.quizlet.quizletandroid.ui.setcreation.managers;

import com.quizlet.db.data.models.persisted.DBStudySet;
import java.util.List;
import java.util.concurrent.TimeUnit;

/* loaded from: classes3.dex */
public final /* synthetic */ class e implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ i b;

    public /* synthetic */ e(i iVar) {
        this.a = 0;
        this.b = iVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        g gVar;
        switch (this.a) {
            case 0:
                i iVar = this.b;
                iVar.getClass();
                long localId = ((DBStudySet) obj).getLocalId();
                long seconds = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
                p pVar = iVar.f;
                pVar.getClass();
                pVar.a.edit().putLong(String.valueOf(localId), seconds).apply();
                break;
            case 1:
                List list = (List) obj;
                i iVar2 = this.b;
                iVar2.e.a = false;
                timber.log.c.a.a("Completed publishing set with %d errors", Integer.valueOf(list.size()));
                if (!list.isEmpty() && (gVar = (g) iVar2.p.get()) != null) {
                    gVar.f(((com.quizlet.infra.legacysyncengine.net.request.c) list.get(0)).a());
                }
                g gVar2 = (g) iVar2.p.get();
                if (gVar2 != null) {
                    gVar2.k(true);
                    break;
                }
                break;
            default:
                i iVar3 = this.b;
                iVar3.getClass();
                timber.log.c.a(new IllegalStateException("Received an error while trying to publish set", (Throwable) obj));
                g gVar3 = (g) iVar3.p.get();
                if (gVar3 != null) {
                    gVar3.k(false);
                    break;
                }
                break;
        }
    }

    public /* synthetic */ e(i iVar, int i, int i2) {
        this.a = i2;
        this.b = iVar;
    }
}
