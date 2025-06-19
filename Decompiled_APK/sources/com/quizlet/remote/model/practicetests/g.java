package com.quizlet.remote.model.practicetests;

import androidx.compose.ui.node.B;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.ads.C3;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.service.r;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C3 k;
    public final /* synthetic */ long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(C3 c3, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c3;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        C3 c3 = this.k;
        if (i == 0) {
            Z.e(obj);
            r rVar = (r) c3.a;
            String strF = B.f("toString(...)");
            this.j = 1;
            obj = rVar.c(strF, this.l, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        RemoteQuestionBanksResponse remoteQuestionBanksResponse = (RemoteQuestionBanksResponse) ((ApiThreeWrapper) obj).a();
        return remoteQuestionBanksResponse != null ? (List) ((com.quizlet.quizletandroid.managers.upgrade.a) c3.c).a(remoteQuestionBanksResponse) : K.a;
    }
}
