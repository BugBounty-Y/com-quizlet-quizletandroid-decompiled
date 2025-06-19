package com.quizlet.features.settings.data.interactor;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.L;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.api.model.ChangePasswordRequest;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;
    public final /* synthetic */ com.quizlet.data.repository.qclass.c k;
    public final /* synthetic */ String l;
    public final /* synthetic */ String m;
    public final /* synthetic */ String n;
    public final /* synthetic */ String o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(com.quizlet.data.repository.qclass.c cVar, String str, String str2, String str3, String str4, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.k = cVar;
        this.l = str;
        this.m = str2;
        this.n = str3;
        this.o = str4;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new i(this.k, this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((i) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
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
        String str = this.l;
        String str2 = this.m;
        String str3 = this.n;
        String str4 = this.o;
        io.reactivex.rxjava3.internal.operators.single.d dVar2 = new io.reactivex.rxjava3.internal.operators.single.d(dVar.d.o(new ChangePasswordRequest(str, str2, str3, str4)).l(dVar.b).h(dVar.c).e(new com.quizlet.quizletandroid.ui.usersettings.b(dVar, 0)).e(new L(str4, 4)).e(new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(15)), new com.quizlet.quizletandroid.ui.usersettings.c(dVar, 1), 2);
        this.j = 1;
        Object objB = I1.b(dVar2, this);
        return objB == aVar ? aVar : objB;
    }
}
