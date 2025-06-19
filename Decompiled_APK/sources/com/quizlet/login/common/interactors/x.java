package com.quizlet.login.common.interactors;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class x extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.onetrust.otpublishers.headless.UI.TVUI.datautils.d k;
    public final /* synthetic */ Map l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public x(com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar, Map map, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = dVar;
        this.l = map;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new x(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((x) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        io.ktor.client.plugins.api.d dVar = (io.ktor.client.plugins.api.d) this.k.a;
        try {
            if (i == 0) {
                Z.e(obj);
                io.reactivex.rxjava3.internal.operators.single.g gVarK = dVar.k(this.l);
                this.j = 1;
                obj = I1.b(gVarK, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            return (com.quizlet.login.authentication.data.i) obj;
        } catch (Exception e) {
            return dVar.x(null, e);
        }
    }
}
