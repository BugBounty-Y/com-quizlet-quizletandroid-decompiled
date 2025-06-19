package com.quizlet.remote.model.union.studysetwithcreator;

import com.google.android.gms.internal.mlkit_vision_barcode.Q;
import com.quizlet.data.model.A1;
import com.quizlet.data.model.C4109a2;
import com.quizlet.data.model.C4113b2;
import com.quizlet.data.model.User;
import com.quizlet.data.model.search.d;
import com.quizlet.quizletandroid.ui.joincontenttofolder.j;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.base.PagingInfo;
import com.quizlet.remote.model.search.RemoteSearchSocialSignalForSets;
import com.quizlet.remote.model.set.RemoteSet;
import com.quizlet.remote.model.union.studysetwithcreator.StudySetsWithCreatorsAndClassificationsResponse;
import com.quizlet.remote.model.user.RemoteUser;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.r;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class a implements h {
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r6v0, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r6v1, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r6v2, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r7v0, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r7v1, types: [java.lang.Iterable] */
    /* JADX WARN: Type inference failed for: r7v2, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r8v0, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r8v1, types: [java.lang.Iterable] */
    /* JADX WARN: Type inference failed for: r8v2, types: [java.util.ArrayList] */
    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        ?? arrayList;
        ?? arrayList2;
        ?? arrayList3;
        List<RemoteSet> list;
        Object next;
        Object next2;
        List list2;
        List list3;
        PagingInfo pagingInfo;
        K response = (K) obj;
        Intrinsics.checkNotNullParameter(response, "response");
        r rVar = response.a.f;
        ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) response.b;
        StudySetsWithCreatorsAndClassificationsResponse studySetsWithCreatorsAndClassificationsResponse = apiThreeWrapper != null ? (StudySetsWithCreatorsAndClassificationsResponse) apiThreeWrapper.a() : null;
        StudySetsWithCreatorsAndClassificationsResponse.Models models = studySetsWithCreatorsAndClassificationsResponse != null ? studySetsWithCreatorsAndClassificationsResponse.d : null;
        A1 a1I = (studySetsWithCreatorsAndClassificationsResponse == null || (pagingInfo = studySetsWithCreatorsAndClassificationsResponse.a) == null) ? null : com.quizlet.quizletandroid.ui.folder.logging.a.i(pagingInfo);
        String strA = Q.a(rVar);
        if (models == null || (list3 = models.b) == null) {
            arrayList = kotlin.collections.K.a;
        } else {
            arrayList = new ArrayList(C.q(list3, 10));
            Iterator it2 = list3.iterator();
            while (it2.hasNext()) {
                arrayList.add(com.quizlet.quizletandroid.ui.activitycenter.models.a.b((RemoteUser) it2.next()));
            }
        }
        if (models == null || (list2 = models.d) == null) {
            arrayList2 = kotlin.collections.K.a;
        } else {
            arrayList2 = new ArrayList(C.q(list2, 10));
            Iterator it3 = list2.iterator();
            while (it3.hasNext()) {
                arrayList2.add(j.j((RemoteSearchSocialSignalForSets) it3.next()));
            }
        }
        if (models == null || (list = models.a) == null) {
            arrayList3 = kotlin.collections.K.a;
        } else {
            arrayList3 = new ArrayList(C.q(list, 10));
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
                    if (((d) next2).a == remoteSet.a) {
                        break;
                    }
                }
                arrayList3.add(new C4113b2(com.quizlet.quizletandroid.ui.profile.data.b.b(remoteSet), user, (d) next2));
            }
        }
        return new C4109a2(arrayList3, a1I, strA);
    }
}
