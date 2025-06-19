package com.quizlet.remote.model.user.delete;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.data.interactor.user.delete.FailedDeleteAccountException;
import com.quizlet.remote.service.E;
import io.reactivex.rxjava3.core.p;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.r;
import kotlinx.coroutines.C;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ c k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, h hVar) {
        super(2, hVar);
        this.k = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objB;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                Z.e(obj);
                p<K<DeleteUserAccountResponse>> pVarC = ((E) this.k.a).c();
                this.j = 1;
                obj = I1.b(pVarC, this);
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
            DeleteUserAccountResponse deleteUserAccountResponse = (DeleteUserAccountResponse) ((K) obj).b;
            if (deleteUserAccountResponse != null ? Intrinsics.b(deleteUserAccountResponse.d, Boolean.TRUE) : false) {
                kotlin.p pVar = r.b;
                objB = Unit.a;
            } else {
                kotlin.p pVar2 = r.b;
                objB = Z.b(new FailedDeleteAccountException());
            }
        } catch (Exception e) {
            kotlin.p pVar3 = r.b;
            objB = Z.b(e);
        }
        return new r(objB);
    }
}
