package com.quizlet.quizletandroid.util;

import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import com.quizlet.db.data.models.wrappers.LoggedInUserStatus;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ e b;

    public /* synthetic */ c(e eVar, int i) {
        this.a = i;
        this.b = eVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                LoggedInUserStatus p0 = (LoggedInUserStatus) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                e eVar = this.b;
                eVar.getClass();
                boolean zIsLoggedIn = p0.isLoggedIn();
                com.quizlet.infra.legacysyncengine.datasources.f fVar = eVar.f;
                com.quizlet.infra.legacysyncengine.net.c cVar = eVar.a;
                if (!zIsLoggedIn) {
                    eVar.c.clear();
                    com.quizlet.infra.legacysyncengine.orm.query.a aVar = eVar.d;
                    if (aVar != null) {
                        cVar.a(aVar, fVar);
                        eVar.d = null;
                        break;
                    }
                } else {
                    com.quizlet.infra.legacysyncengine.managers.d dVar = eVar.b;
                    if (dVar.e.getPersonId() != 0 && eVar.d == null) {
                        com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.GROUP_MEMBERSHIP);
                        bVar.b(Long.valueOf(dVar.e.getPersonId()), DBGroupMembershipFields.USER);
                        com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
                        eVar.d = aVarA;
                        cVar.e(aVarA, fVar);
                        break;
                    }
                }
                break;
            default:
                List it2 = (List) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.c.addAll(it2);
                break;
        }
    }
}
