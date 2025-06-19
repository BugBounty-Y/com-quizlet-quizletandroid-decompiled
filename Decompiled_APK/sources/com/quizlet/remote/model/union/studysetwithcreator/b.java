package com.quizlet.remote.model.union.studysetwithcreator;

import com.quizlet.data.model.U1;
import com.quizlet.data.model.User;
import com.quizlet.data.model.W1;
import com.quizlet.data.model.Z1;
import com.quizlet.quizletandroid.ui.profile.p;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.set.RemoteSet;
import com.quizlet.remote.model.set.RemoteSetClassification;
import com.quizlet.remote.model.union.studysetwithcreator.StudySetsWithCreatorsAndClassificationsResponse;
import com.quizlet.remote.model.user.RemoteUser;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements h {
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r3v0, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r3v1, types: [java.lang.Iterable] */
    /* JADX WARN: Type inference failed for: r3v2, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r4v0, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r4v1, types: [java.lang.Iterable] */
    /* JADX WARN: Type inference failed for: r4v2, types: [java.util.ArrayList] */
    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        ?? arrayList;
        ?? arrayList2;
        List<RemoteSet> list;
        Object next;
        Object next2;
        List list2;
        List list3;
        ApiThreeWrapper wrapper = (ApiThreeWrapper) obj;
        Intrinsics.checkNotNullParameter(wrapper, "wrapper");
        StudySetsWithCreatorsAndClassificationsResponse studySetsWithCreatorsAndClassificationsResponse = (StudySetsWithCreatorsAndClassificationsResponse) wrapper.a();
        StudySetsWithCreatorsAndClassificationsResponse.Models models = studySetsWithCreatorsAndClassificationsResponse != null ? studySetsWithCreatorsAndClassificationsResponse.d : null;
        if (models == null || (list3 = models.b) == null) {
            arrayList = K.a;
        } else {
            arrayList = new ArrayList(C.q(list3, 10));
            Iterator it2 = list3.iterator();
            while (it2.hasNext()) {
                arrayList.add(com.quizlet.quizletandroid.ui.activitycenter.models.a.b((RemoteUser) it2.next()));
            }
        }
        if (models == null || (list2 = models.c) == null) {
            arrayList2 = K.a;
        } else {
            arrayList2 = new ArrayList(C.q(list2, 10));
            Iterator it3 = list2.iterator();
            while (it3.hasNext()) {
                arrayList2.add(p.j((RemoteSetClassification) it3.next()));
            }
        }
        if (models == null || (list = models.a) == null) {
            return K.a;
        }
        ArrayList arrayList3 = new ArrayList(C.q(list, 10));
        for (RemoteSet remoteSet : list) {
            Iterator it4 = arrayList.iterator();
            while (true) {
                if (!it4.hasNext()) {
                    next = null;
                    break;
                }
                next = it4.next();
                long j = ((User) next).a;
                Long l = remoteSet.e;
                if (l != null && j == l.longValue()) {
                    break;
                }
            }
            User user = (User) next;
            Iterator it5 = arrayList2.iterator();
            while (true) {
                if (!it5.hasNext()) {
                    next2 = null;
                    break;
                }
                next2 = it5.next();
                if (((U1) next2).a == remoteSet.a) {
                    break;
                }
            }
            arrayList3.add(new Z1(com.quizlet.quizletandroid.ui.profile.data.b.b(remoteSet), user, new W1((U1) next2)));
        }
        return arrayList3;
    }
}
