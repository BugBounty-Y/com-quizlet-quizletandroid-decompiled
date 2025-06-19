package com.quizlet.remote.model.practicetests;

import androidx.compose.ui.node.B;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.ads.C3;
import com.quizlet.data.exceptions.practicetests.PracticeTestsException;
import com.quizlet.data.model.K0;
import com.quizlet.data.model.M0;
import com.quizlet.data.model.N0;
import com.quizlet.data.model.S;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.service.r;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C3 k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(C3 c3, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c3;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws PracticeTestsException {
        List list;
        List list2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        C3 c3 = this.k;
        if (i == 0) {
            Z.e(obj);
            c3.a();
            r rVar = (r) c3.a;
            String strF = B.f("toString(...)");
            String strB = ((C4636c) c3.i).b();
            this.j = 1;
            obj = rVar.a(this.l, strF, strB, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        RemotePracticeTestResponse remotePracticeTestResponse = (RemotePracticeTestResponse) ((ApiThreeWrapper) obj).a();
        PracticeTestRedirect practiceTestRedirect = null;
        PracticeTestResponse practiceTestResponse = remotePracticeTestResponse != null ? remotePracticeTestResponse.d : null;
        PracticeTestModel practiceTestModel = (practiceTestResponse == null || (list2 = practiceTestResponse.a) == null) ? null : (PracticeTestModel) CollectionsKt.L(list2);
        if (practiceTestResponse != null && (list = practiceTestResponse.b) != null) {
            practiceTestRedirect = (PracticeTestRedirect) CollectionsKt.L(list);
        }
        if (practiceTestModel == null) {
            if (practiceTestRedirect != null) {
                return new N0(practiceTestRedirect.a, practiceTestRedirect.b);
            }
            throw new PracticeTestsException("Practice Test data should not be null");
        }
        K0 k0 = (K0) ((com.quizlet.quizletandroid.ui.setcreation.adapters.a) c3.j).a(practiceTestModel.g);
        com.quizlet.local.ormlite.models.term.b bVar = (com.quizlet.local.ormlite.models.term.b) c3.f;
        List input = practiceTestModel.h;
        Intrinsics.checkNotNullParameter(input, "input");
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(input, 10));
        Iterator it2 = input.iterator();
        while (it2.hasNext()) {
            arrayList.add(bVar.a(it2.next()));
        }
        return new M0(practiceTestModel.a, practiceTestModel.e, practiceTestModel.b, k0, arrayList, (S) ((com.quizlet.quizletandroid.ui.profile.b) c3.k).a(CollectionsKt.L(practiceTestResponse.c)));
    }
}
