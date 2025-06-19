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
public final class a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C3 k;
    public final /* synthetic */ String l;
    public final /* synthetic */ String m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(C3 c3, String str, String str2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c3;
        this.l = str;
        this.m = str2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new a(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws PracticeTestsException {
        RemoteCopyPracticeTestModel remoteCopyPracticeTestModel;
        List list;
        RemoteCopyPracticeTestUuid remoteCopyPracticeTestUuid;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C3 c3 = this.k;
            c3.a();
            r rVar = (r) c3.a;
            String str = this.l;
            String str2 = this.m;
            CopyPracticeTestBody copyPracticeTestBody = new CopyPracticeTestBody(str, str2);
            String strF = B.f("toString(...)");
            this.j = 1;
            obj = rVar.h(copyPracticeTestBody, str2, strF, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        RemoteCopyPracticeTestResponse remoteCopyPracticeTestResponse = (RemoteCopyPracticeTestResponse) ((ApiThreeWrapper) obj).a();
        String str3 = (remoteCopyPracticeTestResponse == null || (remoteCopyPracticeTestModel = remoteCopyPracticeTestResponse.d) == null || (list = remoteCopyPracticeTestModel.a) == null || (remoteCopyPracticeTestUuid = (RemoteCopyPracticeTestUuid) CollectionsKt.L(list)) == null) ? null : remoteCopyPracticeTestUuid.a;
        if (str3 != null) {
            return str3;
        }
        throw new PracticeTestsException("Copied Practice Test Id should not be null");
    }
}
