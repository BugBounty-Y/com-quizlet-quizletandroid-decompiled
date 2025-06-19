package com.quizlet.remote.model.practicetests;

import androidx.compose.ui.node.B;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.ads.C3;
import com.quizlet.data.exceptions.practicetests.PracticeTestsException;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.service.r;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C3 k;
    public final /* synthetic */ String l;
    public final /* synthetic */ String m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(C3 c3, String str, String str2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c3;
        this.l = str;
        this.m = str2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws PracticeTestsException {
        RemoteUpdateGradedAnswerModel remoteUpdateGradedAnswerModel;
        List list;
        RemoteUpdateQuestionUuid remoteUpdateQuestionUuid;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C3 c3 = this.k;
            c3.a();
            r rVar = (r) c3.a;
            UpdateGradedAnswerBody updateGradedAnswerBody = new UpdateGradedAnswerBody(true);
            String strF = B.f("toString(...)");
            this.j = 1;
            obj = rVar.g(updateGradedAnswerBody, this.l, this.m, strF, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        RemoteUpdateGradedAnswerResponse remoteUpdateGradedAnswerResponse = (RemoteUpdateGradedAnswerResponse) ((ApiThreeWrapper) obj).a();
        String str = (remoteUpdateGradedAnswerResponse == null || (remoteUpdateGradedAnswerModel = remoteUpdateGradedAnswerResponse.d) == null || (list = remoteUpdateGradedAnswerModel.a) == null || (remoteUpdateQuestionUuid = (RemoteUpdateQuestionUuid) CollectionsKt.L(list)) == null) ? null : remoteUpdateQuestionUuid.a;
        if (str != null) {
            return str;
        }
        throw new PracticeTestsException("Updated Question Id should not be null");
    }
}
