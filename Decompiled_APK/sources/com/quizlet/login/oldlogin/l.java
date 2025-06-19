package com.quizlet.login.oldlogin;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.X;
import com.quizlet.db.data.models.persisted.DBUser;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ o k;
    public final /* synthetic */ DBUser l;
    public final /* synthetic */ boolean m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(o oVar, DBUser dBUser, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = oVar;
        this.l = dBUser;
        this.m = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new l(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((l) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        o oVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.google.firebase.crashlytics.internal.settings.b bVar = oVar.m;
            this.j = 1;
            obj = bVar.d(this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        boolean zBooleanValue = ((Boolean) obj).booleanValue();
        oVar.f.s(oVar.w, this.l);
        boolean z = this.m;
        X x = oVar.t;
        if (z) {
            x.j(new f(zBooleanValue));
        } else {
            x.j(new d(zBooleanValue));
        }
        return Unit.a;
    }
}
