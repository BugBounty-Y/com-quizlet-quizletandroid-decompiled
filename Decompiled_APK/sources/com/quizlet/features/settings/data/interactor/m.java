package com.quizlet.features.settings.data.interactor;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.DataWrapper;
import com.quizlet.api.model.ReauthenticationRequest;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;
    public final /* synthetic */ com.quizlet.data.repository.qclass.c k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(com.quizlet.data.repository.qclass.c cVar, String str, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.k = cVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new m(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((m) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.quizletandroid.ui.usersettings.d dVar = (com.quizlet.quizletandroid.ui.usersettings.d) this.k.b;
            dVar.getClass();
            io.reactivex.rxjava3.internal.operators.single.g gVarE = dVar.d.k(new ReauthenticationRequest(null, this.l, null)).l(dVar.b).h(dVar.c).e(new com.quizlet.quizletandroid.ui.usersettings.b(dVar, 0)).e(new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(11));
            this.j = 1;
            obj = I1.b(gVarE, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        Intrinsics.checkNotNullExpressionValue(obj, "await(...)");
        return ((DataWrapper) ((ApiResponse) obj).getDataWrapper()).getAuthentication().getReauthToken();
    }
}
