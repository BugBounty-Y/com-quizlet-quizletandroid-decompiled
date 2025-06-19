package com.quizlet.learn.checkpoint.data;

import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.infra.legacysyncengine.managers.i;
import com.quizlet.remote.model.notes.e;
import java.time.Instant;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ e b;
    public final /* synthetic */ long c;

    public /* synthetic */ b(e eVar, long j, int i) {
        this.a = i;
        this.b = eVar;
        this.c = j;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        e eVar = this.b;
        Object obj2 = null;
        long j = this.c;
        switch (this.a) {
            case 0:
                List list = (List) obj;
                Intrinsics.d(list);
                Iterator it2 = list.iterator();
                while (true) {
                    if (it2.hasNext()) {
                        Object next = it2.next();
                        if (((DBSelectedTerm) next).getTermId() == j) {
                            obj2 = next;
                        }
                    }
                }
                DBSelectedTerm dBSelectedTerm = (DBSelectedTerm) obj2;
                if (dBSelectedTerm == null || dBSelectedTerm.getDeleted()) {
                    i iVar = (i) eVar.b;
                    Long l = (Long) eVar.e;
                    Intrinsics.d(l);
                    long jLongValue = l.longValue();
                    Long l2 = (Long) eVar.d;
                    Intrinsics.d(l2);
                    long jLongValue2 = l2.longValue();
                    Instant instantNow = Instant.now();
                    Intrinsics.checkNotNullExpressionValue(instantNow, "now(...)");
                    iVar.c(new DBSelectedTerm(jLongValue, jLongValue2, this.c, instantNow.getEpochSecond(), 8));
                    break;
                }
                break;
            default:
                List list2 = (List) obj;
                Intrinsics.d(list2);
                Iterator it3 = list2.iterator();
                while (true) {
                    if (it3.hasNext()) {
                        Object next2 = it3.next();
                        if (((DBSelectedTerm) next2).getTermId() == j) {
                            obj2 = next2;
                        }
                    }
                }
                DBSelectedTerm dBSelectedTerm2 = (DBSelectedTerm) obj2;
                if (dBSelectedTerm2 != null) {
                    dBSelectedTerm2.setDeleted(true);
                    ((i) eVar.b).c(dBSelectedTerm2);
                    break;
                }
                break;
        }
    }
}
