package com.quizlet.quizletandroid.util;

import android.content.Intent;
import androidx.fragment.app.I;
import com.quizlet.db.data.models.persisted.DBGroupSet;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.w;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final com.quizlet.infra.legacysyncengine.net.f a;
    public final e b;
    public final EventLogger c;
    public final com.quizlet.features.notes.a d;
    public final d e;

    public a(com.quizlet.infra.legacysyncengine.net.f syncDispatcher, e groupSetManager, EventLogger eventLogger, com.quizlet.features.notes.a classContentLogger, d snackbarHelper) {
        Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
        Intrinsics.checkNotNullParameter(groupSetManager, "groupSetManager");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(classContentLogger, "classContentLogger");
        Intrinsics.checkNotNullParameter(snackbarHelper, "snackbarHelper");
        this.a = syncDispatcher;
        this.b = groupSetManager;
        this.c = eventLogger;
        this.d = classContentLogger;
        this.e = snackbarHelper;
    }

    public final void a(I activity, Intent intent, Function1 onComplete) throws Exception {
        Iterable classesIds;
        Object next;
        Intrinsics.checkNotNullParameter(activity, "activity");
        Intrinsics.checkNotNullParameter(intent, "intent");
        Intrinsics.checkNotNullParameter(onComplete, "onComplete");
        long[] longArrayExtra = intent.getLongArrayExtra("setsIds");
        List setsIds = longArrayExtra != null ? C4933y.O(longArrayExtra) : null;
        long[] longArrayExtra2 = intent.getLongArrayExtra("selectedClassIds");
        if (longArrayExtra2 == null || (classesIds = C4933y.O(longArrayExtra2)) == null) {
            classesIds = K.a;
        }
        if (setsIds == null || setsIds.isEmpty() || activity.isFinishing()) {
            return;
        }
        e eVar = this.b;
        eVar.getClass();
        Intrinsics.checkNotNullParameter(setsIds, "setsIds");
        Intrinsics.checkNotNullParameter(classesIds, "classesIds");
        long personId = eVar.b.e.getPersonId();
        ArrayList arrayList = new ArrayList();
        HashSet hashSet = eVar.e;
        ArrayList arrayListY0 = CollectionsKt.y0(hashSet);
        Iterator it2 = setsIds.iterator();
        while (it2.hasNext()) {
            long jLongValue = ((Number) it2.next()).longValue();
            Iterator it3 = classesIds.iterator();
            while (it3.hasNext()) {
                long jLongValue2 = ((Number) it3.next()).longValue();
                Iterator it4 = hashSet.iterator();
                while (true) {
                    if (!it4.hasNext()) {
                        next = null;
                        break;
                    }
                    next = it4.next();
                    DBGroupSet dBGroupSet = (DBGroupSet) next;
                    if (dBGroupSet.getSetId() == jLongValue && dBGroupSet.getClassId() == jLongValue2) {
                        break;
                    }
                }
                DBGroupSet dBGroupSet2 = (DBGroupSet) next;
                if (dBGroupSet2 != null) {
                    arrayListY0.remove(dBGroupSet2);
                } else {
                    DBGroupSet dBGroupSetCreateNewInstance = DBGroupSet.createNewInstance(jLongValue2, jLongValue, personId);
                    Intrinsics.checkNotNullExpressionValue(dBGroupSetCreateNewInstance, "createNewInstance(...)");
                    arrayList.add(dBGroupSetCreateNewInstance);
                }
            }
        }
        Iterator it5 = arrayListY0.iterator();
        while (it5.hasNext()) {
            ((DBGroupSet) it5.next()).setDeleted(true);
        }
        if (arrayList.isEmpty() && arrayListY0.isEmpty()) {
            return;
        }
        this.c.I("add_to_class_finished_with_changes");
        this.a.b(CollectionsKt.c0(arrayList, arrayListY0));
        this.d.b(arrayListY0, arrayList);
        onComplete.invoke(new com.quizlet.features.setpage.managers.a(setsIds.size(), new w(this, arrayList, arrayListY0, 3)));
    }
}
