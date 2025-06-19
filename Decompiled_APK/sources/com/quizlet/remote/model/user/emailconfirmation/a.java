package com.quizlet.remote.model.user.emailconfirmation;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.EnumC4171u1;
import com.quizlet.remote.model.base.ApiError;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.service.NetworkException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public c j;
    public int k;
    public final /* synthetic */ c l;
    public final /* synthetic */ b m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(c cVar, b bVar, h hVar) {
        super(2, hVar);
        this.l = cVar;
        this.m = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        c cVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                c cVar2 = this.l;
                b bVar = this.m;
                this.j = cVar2;
                this.k = 1;
                Object objInvoke = bVar.invoke(this);
                if (objInvoke == aVar) {
                    return aVar;
                }
                cVar = cVar2;
                obj = objInvoke;
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                cVar = this.j;
                Z.e(obj);
            }
            return c.b(cVar, (ApiThreeWrapper) obj);
        } catch (NetworkException e) {
            ApiError apiError = e.a;
            if (Intrinsics.b(apiError != null ? apiError.b : null, "exception_too_many_confirmation_resends")) {
                return EnumC4171u1.c;
            }
            throw e;
        }
    }
}
