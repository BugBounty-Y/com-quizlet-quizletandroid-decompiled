package com.quizlet.remote.model.practicetests;

import androidx.compose.ui.node.B;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.ads.C3;
import com.quizlet.data.exceptions.practicetests.PracticeTestsException;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.service.r;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C3 k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(C3 c3, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c3;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws PracticeTestsException {
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
            obj = rVar.f(this.l, strF, strB, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        RemotePracticeTestResultResponse remotePracticeTestResultResponse = (RemotePracticeTestResultResponse) ((ApiThreeWrapper) obj).a();
        if (remotePracticeTestResultResponse != null) {
            return ((com.quizlet.data.repository.login.a) c3.e).a(remotePracticeTestResultResponse);
        }
        throw new PracticeTestsException("Practice Test Result should not be null");
    }
}
