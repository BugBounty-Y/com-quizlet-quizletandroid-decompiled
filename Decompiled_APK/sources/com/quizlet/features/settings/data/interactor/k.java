package com.quizlet.features.settings.data.interactor;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.api.model.ChangeUsernameRequest;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;
    public final /* synthetic */ com.quizlet.data.repository.qclass.c k;
    public final /* synthetic */ String l;
    public final /* synthetic */ String m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(com.quizlet.data.repository.qclass.c cVar, String str, String str2, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.k = cVar;
        this.l = str;
        this.m = str2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new k(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((k) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        com.quizlet.quizletandroid.ui.usersettings.d dVar = (com.quizlet.quizletandroid.ui.usersettings.d) this.k.b;
        dVar.getClass();
        io.reactivex.rxjava3.internal.operators.single.g gVarE = new io.reactivex.rxjava3.internal.operators.single.d(dVar.d.l(new ChangeUsernameRequest(this.m, this.l)).l(dVar.b).h(dVar.c).e(new com.quizlet.quizletandroid.ui.usersettings.b(dVar, 0)), new com.quizlet.quizletandroid.ui.usersettings.c(dVar, 0), 2).e(new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(8));
        this.j = 1;
        Object objB = I1.b(gVarE, this);
        return objB == aVar ? aVar : objB;
    }
}
