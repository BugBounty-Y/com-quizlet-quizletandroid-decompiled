package com.quizlet.quizletandroid.ui.activitycenter.views;

import android.net.Uri;
import android.util.SparseArray;
import android.view.View;
import androidx.camera.camera2.internal.C0128e;
import com.google.android.gms.internal.ads.C2824xF;
import com.google.android.gms.internal.ads.Zh;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.data.model.AbstractC4165s1;
import com.quizlet.data.model.C4112b1;
import com.quizlet.data.model.C4160q1;
import com.quizlet.data.model.Q0;
import com.quizlet.data.model.R0;
import com.quizlet.data.model.User;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.generated.enums.A0;
import com.quizlet.generated.enums.C4504n0;
import com.quizlet.generated.enums.C4531x0;
import com.quizlet.generated.enums.C4535z0;
import com.quizlet.generated.enums.EnumC4501m0;
import com.quizlet.generated.enums.EnumC4507o0;
import com.quizlet.generated.enums.EnumC4533y0;
import com.quizlet.generated.enums.w1;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.ui.group.addclassset.AddClassSetActivity;
import com.quizlet.quizletandroid.ui.group.addclassset.AddToClassSetListFragment;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4723t;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.P;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.practicetests.PracticeTestGradedQuestionResponse;
import com.quizlet.remote.model.practicetests.PracticeTestsAnswerOptionResponse;
import com.quizlet.remote.model.practicetests.PracticeTestsImageDataResponse;
import com.quizlet.remote.model.set.RecommendedSetsBehaviorBasedResponse;
import com.quizlet.remote.model.set.RemoteSet;
import com.quizlet.remote.model.user.RemoteUser;
import com.quizlet.remote.service.E;
import com.quizlet.shared.models.api.metering.MeteredEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;
import retrofit2.C5183h;
import retrofit2.InterfaceC5179d;
import retrofit2.InterfaceC5182g;

/* loaded from: classes3.dex */
public final class i implements f, com.quizlet.features.infra.legacyadapter.d, com.quizlet.qutils.image.capture.b, io.reactivex.rxjava3.functions.h, com.quizlet.mapper.a, InterfaceC5182g {
    public final /* synthetic */ int a;
    public final Object b;

    public i(com.iabtcf.decoder.d closure) {
        this.a = 11;
        Intrinsics.checkNotNullParameter(closure, "closure");
        this.b = closure;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r9v1 */
    /* JADX WARN: Type inference failed for: r9v2 */
    /* JADX WARN: Type inference failed for: r9v3, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r9v4, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r9v5, types: [java.util.ArrayList] */
    @Override // com.quizlet.mapper.a
    public Object a(Object obj) {
        Map mapC;
        ?? arrayList;
        PracticeTestGradedQuestionResponse input = (PracticeTestGradedQuestionResponse) obj;
        Intrinsics.checkNotNullParameter(input, "input");
        Map map = input.d;
        com.quizlet.quizletandroid.logging.initializer.a aVar = (com.quizlet.quizletandroid.logging.initializer.a) this.b;
        A0 a0A = null;
        if (map != null) {
            mapC = new LinkedHashMap(U.a(map.size()));
            for (Map.Entry entry : map.entrySet()) {
                Object key = entry.getKey();
                PracticeTestsAnswerOptionResponse practiceTestsAnswerOptionResponse = (PracticeTestsAnswerOptionResponse) entry.getValue();
                String str = practiceTestsAnswerOptionResponse.a;
                List list = practiceTestsAnswerOptionResponse.b;
                if (list != null) {
                    arrayList = new ArrayList(C.q(list, 10));
                    Iterator it2 = list.iterator();
                    while (it2.hasNext()) {
                        arrayList.add((R0) aVar.a((PracticeTestsImageDataResponse) it2.next()));
                    }
                } else {
                    arrayList = 0;
                }
                if (arrayList == 0) {
                    arrayList = K.a;
                }
                mapC.put(key, new C4112b1(str, arrayList));
            }
        } else {
            mapC = null;
        }
        if (mapC == null) {
            mapC = V.c();
        }
        Map map2 = mapC;
        ArrayList arrayList2 = new ArrayList();
        List list2 = input.i;
        if (list2 != null) {
            Iterator it3 = list2.iterator();
            while (it3.hasNext()) {
                arrayList2.add(aVar.a((PracticeTestsImageDataResponse) it3.next()));
            }
        }
        EnumC4533y0.Companion.getClass();
        EnumC4533y0 enumC4533y0A = C4531x0.a(input.e);
        EnumC4501m0.Companion.getClass();
        for (EnumC4501m0 enumC4501m0 : EnumC4501m0.values()) {
            if (enumC4501m0.a() == input.h) {
                EnumC4507o0.Companion.getClass();
                EnumC4507o0 enumC4507o0A = C4504n0.a(input.l);
                String str2 = input.m;
                if (str2 != null) {
                    A0.Companion.getClass();
                    a0A = C4535z0.a(str2);
                }
                return new Q0(input.a, input.b, input.g, input.c, map2, enumC4501m0, enumC4533y0A, input.f, input.j, input.k, enumC4507o0A, arrayList2, a0A);
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        List list;
        List list2;
        C4160q1 c4160q1;
        switch (this.a) {
            case 3:
                ModelType it2 = (ModelType) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return ((com.quizlet.infra.legacysyncengine.net.f) ((Zh) this.b).c).c(it2);
            case 4:
                C4723t recommendedSets = (C4723t) obj;
                Intrinsics.checkNotNullParameter(recommendedSets, "recommendedSets");
                w1 w1Var = w1.BEHAVIORAL_REC;
                ((androidx.work.impl.model.e) this.b).getClass();
                return androidx.work.impl.model.e.w(recommendedSets, w1Var);
            case 5:
                List it3 = (List) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                ((Y) this.b).getClass();
                return it3.isEmpty() ? new ArrayList() : O.b(CollectionsKt.y0(Y.F(Y.G(it3), P.a, null)));
            case 6:
            case 7:
            case 8:
            default:
                Object[] objArr = (Object[]) obj;
                if (objArr.length == 4) {
                    return ((io.reactivex.rxjava3.functions.f) this.b).a(objArr[0], objArr[1], objArr[2], objArr[3]);
                }
                throw new IllegalArgumentException("Array of size 4 expected but got " + objArr.length);
            case 9:
                ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) obj;
                Intrinsics.checkNotNullParameter(apiThreeWrapper, "apiThreeWrapper");
                List<RecommendedSetsBehaviorBasedResponse> responses = apiThreeWrapper.a;
                if (responses == null || !(!responses.isEmpty())) {
                    return new C4160q1(K.a, null, null);
                }
                com.quizlet.remote.model.set.e eVar = (com.quizlet.remote.model.set.e) ((com.quizlet.remote.model.set.d) this.b).b;
                Intrinsics.checkNotNullParameter(responses, "responses");
                ArrayList arrayList = new ArrayList(C.q(responses, 10));
                for (RecommendedSetsBehaviorBasedResponse recommendedSetsBehaviorBasedResponse : responses) {
                    RecommendedSetsBehaviorBasedResponse.RecommendedSetsBehaviorBasedModels recommendedSetsBehaviorBasedModels = recommendedSetsBehaviorBasedResponse.d;
                    if (recommendedSetsBehaviorBasedModels == null || (list = recommendedSetsBehaviorBasedModels.a) == null) {
                        list = K.a;
                    }
                    if (recommendedSetsBehaviorBasedModels == null || (list2 = recommendedSetsBehaviorBasedModels.b) == null) {
                        list2 = K.a;
                    }
                    RecommendedSetsBehaviorBasedResponse.RecommendedSetsBehaviorBasedSource recommendedSetsBehaviorBasedSource = recommendedSetsBehaviorBasedResponse.e;
                    if (recommendedSetsBehaviorBasedSource != null) {
                        ArrayList arrayListD = eVar.b.d(T.f(eVar.a, list), list2);
                        RemoteUser remoteUser = recommendedSetsBehaviorBasedSource.a;
                        User userB = remoteUser != null ? com.quizlet.quizletandroid.ui.activitycenter.models.a.b(remoteUser) : null;
                        RemoteSet remoteSet = recommendedSetsBehaviorBasedSource.b;
                        c4160q1 = new C4160q1(arrayListD, userB, remoteSet != null ? com.quizlet.quizletandroid.ui.profile.data.b.b(remoteSet) : null);
                    } else {
                        c4160q1 = new C4160q1(K.a, null, null);
                    }
                    arrayList.add(c4160q1);
                }
                return (AbstractC4165s1) CollectionsKt.L(arrayList);
        }
    }

    @Override // com.quizlet.features.infra.legacyadapter.d
    public /* bridge */ /* synthetic */ boolean b(View view, int i, DBModel dBModel) {
        return false;
    }

    public boolean c(com.quizlet.shared.enums.h hVar) {
        MeteredEvent meteredEvent;
        return (hVar == null || (meteredEvent = (MeteredEvent) ((LinkedHashMap) this.b).get(hVar)) == null || meteredEvent.a < meteredEvent.b) ? false : true;
    }

    @Override // com.quizlet.features.infra.legacyadapter.d
    public boolean d(View view, int i, DBModel dBModel) {
        DBStudySet dBStudySet = (DBStudySet) dBModel;
        if (dBStudySet == null) {
            return false;
        }
        AddToClassSetListFragment addToClassSetListFragment = (AddToClassSetListFragment) this.b;
        addToClassSetListFragment.v.b(dBStudySet.getId());
        com.quizlet.quizletandroid.ui.group.addclassset.d dVar = (com.quizlet.quizletandroid.ui.group.addclassset.d) addToClassSetListFragment.u.get();
        if (dVar != null) {
            AddClassSetActivity addClassSetActivity = (AddClassSetActivity) dVar;
            for (int i2 = 0; i2 < 3; i2++) {
                AddToClassSetListFragment addToClassSetListFragment2 = (AddToClassSetListFragment) ((BaseFragment) ((SparseArray) addClassSetActivity.p.k).get(i2));
                if (addToClassSetListFragment2 != addToClassSetListFragment) {
                    com.google.mlkit.vision.documentscanner.internal.c cVar = addToClassSetListFragment2.z.f;
                    if ((cVar == null ? -1 : cVar.e().indexOf(dBStudySet)) != -1) {
                        addToClassSetListFragment2.v.b(dBStudySet.getId());
                    }
                }
            }
        }
        return true;
    }

    public void e(com.quizlet.shared.enums.h hVar) {
        if (hVar == null || c(hVar)) {
            return;
        }
        LinkedHashMap linkedHashMap = (LinkedHashMap) this.b;
        MeteredEvent meteredEvent = (MeteredEvent) linkedHashMap.get(hVar);
        if (meteredEvent != null) {
            linkedHashMap.put(hVar, new MeteredEvent(meteredEvent.a + 1, meteredEvent.b));
        }
    }

    @Override // retrofit2.InterfaceC5182g
    public void f(InterfaceC5179d interfaceC5179d, Throwable th) {
        ((C5183h) this.b).completeExceptionally(th);
    }

    @Override // com.quizlet.qutils.image.capture.b
    public void g(Uri uri) {
        ArrayList arrayList;
        C2824xF c2824xF = (C2824xF) this.b;
        DBTerm dBTerm = (DBTerm) c2824xF.f;
        if (dBTerm == null) {
            long j = c2824xF.a;
            if (j != 0) {
                EditSetFragment editSetFragment = (EditSetFragment) c2824xF.d;
                com.google.firebase.tracing.a callback = new com.google.firebase.tracing.a(28, this, uri);
                editSetFragment.getClass();
                Intrinsics.checkNotNullParameter(callback, "callback");
                C0128e c0128e = new C0128e(j, callback, 4);
                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = editSetFragment.A;
                List listUnmodifiableList = null;
                if (fVar != null && (arrayList = fVar.p) != null) {
                    listUnmodifiableList = Collections.unmodifiableList(arrayList);
                }
                if (listUnmodifiableList == null) {
                    editSetFragment.H = c0128e;
                    return;
                } else {
                    c0128e.accept(listUnmodifiableList);
                    return;
                }
            }
        }
        if (dBTerm != null) {
            c2824xF.b(dBTerm, uri);
        }
    }

    @Override // com.quizlet.quizletandroid.ui.activitycenter.views.f
    public QTextView getCount() {
        QTextView count = ((UnreadBadgeViewV2) this.b).q.c;
        Intrinsics.checkNotNullExpressionValue(count, "count");
        return count;
    }

    @Override // com.quizlet.quizletandroid.ui.activitycenter.views.f
    public View h() {
        View dot = ((UnreadBadgeViewV2) this.b).q.d;
        Intrinsics.checkNotNullExpressionValue(dot, "dot");
        return dot;
    }

    @Override // retrofit2.InterfaceC5182g
    public void k(InterfaceC5179d interfaceC5179d, retrofit2.K k) {
        ((C5183h) this.b).complete(k);
    }

    @Override // com.quizlet.qutils.image.capture.b
    public void onCancel() {
        C2824xF c2824xF = (C2824xF) this.b;
        c2824xF.f = null;
        c2824xF.a = 0L;
    }

    public /* synthetic */ i(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public i(com.quizlet.quizletandroid.ui.common.images.capture.b remoteExerciseMapper) {
        this.a = 7;
        Intrinsics.checkNotNullParameter(remoteExerciseMapper, "remoteExerciseMapper");
        this.b = remoteExerciseMapper;
    }

    public i(HashMap meteringData) {
        this.a = 13;
        Intrinsics.checkNotNullParameter(meteringData, "meteringData");
        this.b = V.m(meteringData);
    }

    public i(E service) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(service, "service");
        this.b = service;
    }

    public i(com.quizlet.quizletandroid.logging.initializer.a practiceTestsImageDataMapper) {
        this.a = 8;
        Intrinsics.checkNotNullParameter(practiceTestsImageDataMapper, "practiceTestsImageDataMapper");
        this.b = practiceTestsImageDataMapper;
    }
}
