package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.eventlogger.features.authentication.SignUpWallEventLogger;
import com.quizlet.generated.enums.A1;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class r extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ s k;
    public final /* synthetic */ long l;
    public final /* synthetic */ A1 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(s sVar, long j, A1 a1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = sVar;
        this.l = j;
        this.m = a1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new r(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((r) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        s sVar = this.k;
        if (i == 0) {
            Z.e(obj);
            io.reactivex.rxjava3.internal.operators.single.g gVarR = sVar.e.r();
            this.j = 1;
            obj = I1.b(gVarR, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        if (!((Boolean) obj).booleanValue()) {
            return null;
        }
        SignUpWallEventLogger signUpWallEventLogger = sVar.g;
        A1 a1 = this.m;
        signUpWallEventLogger.c(new com.quizlet.quizletandroid.ui.common.ads.G(a1, 14));
        return new com.quizlet.features.infra.basestudy.data.models.o(this.l, a1);
    }
}
