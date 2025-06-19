package com.quizlet.remote.model.universaluploadflow;

import androidx.compose.ui.node.B;
import androidx.glance.appwidget.protobuf.Z;
import androidx.transition.C1412o;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3355j2;
import com.quizlet.data.exceptions.universaluploadflow.UniversalUploadFlowException;
import com.quizlet.data.model.C4111b0;
import com.quizlet.generated.enums.EnumC4483g0;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.service.D;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import okhttp3.E;
import okhttp3.w;
import okhttp3.y;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.remote.model.notes.e k;
    public final /* synthetic */ boolean l;
    public final /* synthetic */ List m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(com.quizlet.remote.model.notes.e eVar, List list, h hVar, boolean z) {
        super(2, hVar);
        this.k = eVar;
        this.l = z;
        this.m = list;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        boolean z = this.l;
        return new b(this.k, this.m, hVar, z);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Throwable th;
        Object objD;
        UniversalUploadFlowPracticeTestsResponse universalUploadFlowPracticeTestsResponse;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        com.quizlet.remote.model.notes.e eVar = this.k;
        Throwable th2 = null;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.remote.model.notes.e.e(eVar);
            int i2 = 0;
            com.quizlet.data.interactor.set.c cVar = new com.quizlet.data.interactor.set.c(0);
            cVar.r(y.f);
            String value = String.valueOf(this.l);
            Intrinsics.checkNotNullParameter("private", "name");
            Intrinsics.checkNotNullParameter(value, "value");
            Intrinsics.checkNotNullParameter("private", "name");
            Intrinsics.checkNotNullParameter(value, "value");
            cVar.i(AbstractC3355j2.b("private", null, C1412o.f(value, null)));
            List<C4111b0> list = this.m;
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
            for (C4111b0 c4111b0 : list) {
                String str = c4111b0.a;
                Pattern pattern = w.e;
                w wVarD = AbstractC3347h2.d(c4111b0.b);
                byte[] bArr = c4111b0.c;
                int length = bArr.length;
                Intrinsics.checkNotNullParameter(bArr, "<this>");
                okhttp3.internal.b.c(bArr.length, i2, length);
                cVar.h("file[]", str, new E(length, wVarD, bArr));
                arrayList.add(cVar);
                th2 = th2;
                i2 = 0;
            }
            th = th2;
            D d = (D) eVar.b;
            y yVarK = cVar.k();
            String strF = B.f("toString(...)");
            String strB = ((C4636c) eVar.f).b();
            this.j = 1;
            objD = d.d(yVarK, strF, EnumC4483g0.FILE.a(), strB, this);
            if (objD != aVar) {
            }
        }
        if (i != 1) {
            if (i != 2) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        objD = obj;
        th = null;
        K k = (K) objD;
        if (!k.a.d()) {
            com.quizlet.remote.model.notes.e.f(eVar, k);
            throw th;
        }
        ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) k.b;
        UniversalUploadFlowPracticeTestsModels universalUploadFlowPracticeTestsModels = (apiThreeWrapper == null || (universalUploadFlowPracticeTestsResponse = (UniversalUploadFlowPracticeTestsResponse) apiThreeWrapper.a()) == null) ? th : universalUploadFlowPracticeTestsResponse.d;
        if (universalUploadFlowPracticeTestsModels == 0) {
            throw new UniversalUploadFlowException("Failed to retrieve polling parameters");
        }
        List list2 = universalUploadFlowPracticeTestsModels.b;
        UniversalUploadFlowPracticeTestsDocuments universalUploadFlowPracticeTestsDocuments = (UniversalUploadFlowPracticeTestsDocuments) CollectionsKt.firstOrNull(universalUploadFlowPracticeTestsModels.a);
        if (universalUploadFlowPracticeTestsDocuments == null) {
            throw new UniversalUploadFlowException("Failed to generate practice tests");
        }
        String str2 = universalUploadFlowPracticeTestsDocuments.a;
        this.j = 2;
        Object objG = com.quizlet.remote.model.notes.e.g(eVar, list2, str2, this);
        return objG == aVar ? aVar : objG;
    }
}
