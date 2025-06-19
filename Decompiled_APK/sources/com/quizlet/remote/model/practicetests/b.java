package com.quizlet.remote.model.practicetests;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_common.s;
import com.quizlet.data.exceptions.practicetests.PracticeTestCreationException;
import com.quizlet.data.exceptions.practicetests.PracticeTestPaywallException;
import com.quizlet.generated.enums.EnumC4513q0;
import com.quizlet.generated.enums.EnumC4533y0;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.service.r;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.UUID;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import okhttp3.I;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C3 k;
    public final /* synthetic */ String l;
    public final /* synthetic */ int m;
    public final /* synthetic */ ArrayList n;
    public final /* synthetic */ int o;
    public final /* synthetic */ EnumC4513q0 p;
    public final /* synthetic */ Long q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(C3 c3, String str, int i, ArrayList arrayList, int i2, EnumC4513q0 enumC4513q0, Long l, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c3;
        this.l = str;
        this.m = i;
        this.n = arrayList;
        this.o = i2;
        this.p = enumC4513q0;
        this.q = l;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.k, this.l, this.m, this.n, this.o, this.p, this.q, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Exception {
        Object objE;
        RemoteCreatedPracticeTestResponse remoteCreatedPracticeTestResponse;
        RemoteCreatedPracticeTestModel remoteCreatedPracticeTestModel;
        RemoteCreatedPracticeTestUuid remoteCreatedPracticeTestUuid;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                Z.e(obj);
                C3 c3 = this.k;
                c3.a();
                r rVar = (r) c3.a;
                String str = this.l;
                int i2 = this.m;
                ArrayList arrayList = this.n;
                ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    arrayList2.add(((EnumC4533y0) it2.next()).a());
                }
                PracticeTestBody practiceTestBody = new PracticeTestBody(str, i2, new PracticeTestConfiguration(this.o, arrayList2, new Long(0L), null, false, false, 8, null), this.p.a(), new QuestionBankMetadata(this.q), new QuestionCompatibility(null, null, null, 7, null));
                String string = UUID.randomUUID().toString();
                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                this.j = 1;
                objE = rVar.e(practiceTestBody, string, this);
                if (objE == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
                objE = obj;
            }
            K k = (K) objE;
            if (k.a.d()) {
                ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) k.b;
                if (apiThreeWrapper == null || (remoteCreatedPracticeTestResponse = (RemoteCreatedPracticeTestResponse) apiThreeWrapper.a()) == null || (remoteCreatedPracticeTestModel = remoteCreatedPracticeTestResponse.d) == null || (remoteCreatedPracticeTestUuid = (RemoteCreatedPracticeTestUuid) CollectionsKt.L(remoteCreatedPracticeTestModel.a)) == null) {
                    throw new PracticeTestCreationException("Practice Test Id should not be null");
                }
                return remoteCreatedPracticeTestUuid.a;
            }
            if (k.a.d != 403) {
                throw new PracticeTestCreationException(null);
            }
            I i3 = k.c;
            if (i3 == null) {
                throw new PracticeTestCreationException(null);
            }
            s.a(i3);
            throw null;
        } catch (Exception e) {
            if (e instanceof PracticeTestPaywallException) {
                throw e;
            }
            throw new PracticeTestCreationException(e.getMessage());
        }
    }
}
