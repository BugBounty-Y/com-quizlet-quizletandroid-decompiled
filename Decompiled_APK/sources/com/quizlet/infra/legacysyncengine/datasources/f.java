package com.quizlet.infra.legacysyncengine.datasources;

import com.quizlet.db.data.models.persisted.DBGroupSet;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class f implements com.quizlet.infra.legacysyncengine.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ f(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // com.quizlet.infra.legacysyncengine.a
    public final void a(ArrayList groupSets) {
        switch (this.a) {
            case 0:
                h hVar = (h) this.b;
                if (groupSets == null) {
                    hVar.getClass();
                    break;
                } else {
                    hVar.b.b(groupSets);
                    break;
                }
            case 1:
                ((o) this.b).c();
                break;
            case 2:
                p pVar = (p) this.b;
                if (groupSets == null) {
                    pVar.getClass();
                    break;
                } else {
                    pVar.e.b(groupSets);
                    break;
                }
            case 3:
                ((p) this.b).c();
                break;
            case 4:
                ((p) this.b).c();
                break;
            case 5:
                p pVar2 = (p) this.b;
                if (groupSets == null) {
                    pVar2.getClass();
                    break;
                } else {
                    pVar2.e.b(groupSets);
                    break;
                }
            case 6:
                ((io.reactivex.rxjava3.internal.operators.single.c) this.b).onSuccess(groupSets);
                break;
            case 7:
                ((io.reactivex.rxjava3.subjects.b) this.b).b(groupSets);
                break;
            case 8:
                Intrinsics.d(groupSets);
                com.quizlet.quizletandroid.ui.setpage.addset.c cVar = (com.quizlet.quizletandroid.ui.setpage.addset.c) this.b;
                cVar.h = true;
                if (cVar.f.size() == 1) {
                    com.quizlet.features.infra.legacyadapter.helper.a aVar = cVar.e;
                    aVar.a.clear();
                    Iterator it2 = groupSets.iterator();
                    while (it2.hasNext()) {
                        aVar.a.add(Long.valueOf(((DBGroupSet) it2.next()).getClassId()));
                    }
                }
                com.quizlet.quizletandroid.util.a aVar2 = cVar.d;
                aVar2.getClass();
                Intrinsics.checkNotNullParameter(groupSets, "groupSets");
                com.quizlet.quizletandroid.util.e eVar = aVar2.b;
                eVar.getClass();
                Intrinsics.checkNotNullParameter(groupSets, "groupSets");
                HashSet hashSet = eVar.e;
                hashSet.clear();
                hashSet.addAll(groupSets);
                cVar.i.b(groupSets);
                break;
            case 9:
                ArrayList arrayList = (ArrayList) this.b;
                arrayList.clear();
                arrayList.addAll(groupSets);
                break;
            default:
                io.reactivex.rxjava3.core.i.o(groupSets).q(com.quizlet.quizletandroid.util.d.a).x(16).i(new com.quizlet.quizletandroid.util.c((com.quizlet.quizletandroid.util.e) this.b, 1), new com.quizlet.billing.manager.d(timber.log.c.a, 19));
                break;
        }
    }
}
