package com.quizlet.remote.model.practicetests;

import androidx.compose.ui.node.B;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_common.s;
import com.quizlet.data.exceptions.practicetests.PracticeTestsException;
import com.quizlet.data.model.C4108a1;
import com.quizlet.generated.enums.EnumC4513q0;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.service.r;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import okhttp3.I;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C3 k;
    public final /* synthetic */ ArrayList l;
    public final /* synthetic */ EnumC4513q0 m;
    public final /* synthetic */ String n;
    public final /* synthetic */ String o;
    public final /* synthetic */ String p;
    public final /* synthetic */ String q;
    public final /* synthetic */ long r;
    public final /* synthetic */ String s;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(C3 c3, ArrayList arrayList, EnumC4513q0 enumC4513q0, String str, String str2, String str3, String str4, long j, String str5, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c3;
        this.l = arrayList;
        this.m = enumC4513q0;
        this.n = str;
        this.o = str2;
        this.p = str3;
        this.q = str4;
        this.r = j;
        this.s = str5;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.k, this.l, this.m, this.n, this.o, this.p, this.q, this.r, this.s, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws PracticeTestsException {
        Object objD;
        RemoteCreatedPracticeTestResponse remoteCreatedPracticeTestResponse;
        RemoteCreatedPracticeTestModel remoteCreatedPracticeTestModel;
        RemoteCreatedPracticeTestUuid remoteCreatedPracticeTestUuid;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            r rVar = (r) this.k.a;
            ArrayList arrayList = this.l;
            ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                C4108a1 c4108a1 = (C4108a1) it2.next();
                arrayList2.add(new UngradedQuestion(c4108a1.a, c4108a1.b, c4108a1.c.a(), c4108a1.d, c4108a1.e, c4108a1.f));
            }
            PracticeTestMetadata practiceTestMetadata = new PracticeTestMetadata(null, this.m.a());
            GradePracticeTestBody gradePracticeTestBody = new GradePracticeTestBody(this.n, this.o, arrayList2, this.p, this.q, this.r, practiceTestMetadata);
            String strF = B.f("toString(...)");
            this.j = 1;
            objD = rVar.d(gradePracticeTestBody, this.s, strF, this);
            if (objD == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objD = obj;
        }
        K k = (K) objD;
        if (k.a.d()) {
            ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) k.b;
            if (apiThreeWrapper == null || (remoteCreatedPracticeTestResponse = (RemoteCreatedPracticeTestResponse) apiThreeWrapper.a()) == null || (remoteCreatedPracticeTestModel = remoteCreatedPracticeTestResponse.d) == null || (remoteCreatedPracticeTestUuid = (RemoteCreatedPracticeTestUuid) CollectionsKt.L(remoteCreatedPracticeTestModel.a)) == null) {
                throw new PracticeTestsException("Practice Test Id should not be null");
            }
            return remoteCreatedPracticeTestUuid.a;
        }
        if (k.a.d != 403) {
            throw new PracticeTestsException(null);
        }
        I i2 = k.c;
        if (i2 == null) {
            throw new PracticeTestsException(null);
        }
        s.a(i2);
        throw null;
    }
}
