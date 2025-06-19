package com.quizlet.remote.model.universaluploadflow;

import androidx.compose.ui.node.B;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.exceptions.universaluploadflow.UniversalUploadFlowException;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.service.D;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.remote.model.notes.e k;
    public final /* synthetic */ Object l;
    public final /* synthetic */ boolean m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(com.quizlet.remote.model.notes.e eVar, List list, h hVar, boolean z) {
        super(2, hVar);
        this.k = eVar;
        this.l = list;
        this.m = z;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, java.util.List] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new c(this.k, this.l, hVar, this.m);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r6v0, types: [java.lang.Object, java.util.List] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws UniversalUploadFlowException {
        UniversalUploadFlowPracticeTestsResponse universalUploadFlowPracticeTestsResponse;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        com.quizlet.remote.model.notes.e eVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.remote.model.notes.e.e(eVar);
            UploadFlashcardSetPracticeTestsBody uploadFlashcardSetPracticeTestsBody = new UploadFlashcardSetPracticeTestsBody(this.l, this.m, null, null, null, 28, null);
            D d = (D) eVar.b;
            String strF = B.f("toString(...)");
            this.j = 1;
            obj = d.a(uploadFlashcardSetPracticeTestsBody, strF, this);
            if (obj != aVar) {
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
        K k = (K) obj;
        UniversalUploadFlowPracticeTestsModels universalUploadFlowPracticeTestsModels = null;
        if (!k.a.d()) {
            com.quizlet.remote.model.notes.e.f(eVar, k);
            throw null;
        }
        ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) k.b;
        if (apiThreeWrapper != null && (universalUploadFlowPracticeTestsResponse = (UniversalUploadFlowPracticeTestsResponse) apiThreeWrapper.a()) != null) {
            universalUploadFlowPracticeTestsModels = universalUploadFlowPracticeTestsResponse.d;
        }
        if (universalUploadFlowPracticeTestsModels == null) {
            throw new UniversalUploadFlowException("Failed to retrieve polling parameters");
        }
        List list = universalUploadFlowPracticeTestsModels.b;
        UniversalUploadFlowPracticeTestsDocuments universalUploadFlowPracticeTestsDocuments = (UniversalUploadFlowPracticeTestsDocuments) CollectionsKt.firstOrNull(universalUploadFlowPracticeTestsModels.a);
        if (universalUploadFlowPracticeTestsDocuments == null) {
            throw new UniversalUploadFlowException("Failed to generate practice tests");
        }
        String str = universalUploadFlowPracticeTestsDocuments.a;
        this.j = 2;
        Object objG = com.quizlet.remote.model.notes.e.g(eVar, list, str, this);
        return objG == aVar ? aVar : objG;
    }
}
