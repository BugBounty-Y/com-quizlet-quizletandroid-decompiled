package com.quizlet.login.oldlogin;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.quizlet.db.data.models.persisted.DBUser;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public int k;
    public final /* synthetic */ DBUser l;
    public final /* synthetic */ boolean m;
    public final /* synthetic */ o n;
    public final /* synthetic */ String o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(DBUser dBUser, boolean z, o oVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = dBUser;
        this.m = z;
        this.n = oVar;
        this.o = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r7v2 */
    /* JADX WARN: Type inference failed for: r7v3, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r7v4 */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        int i;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i2 = this.k;
        DBUser dBUser = this.l;
        boolean z = this.m;
        o oVar = this.n;
        if (i2 == 0) {
            Z.e(obj);
            ?? r7 = (!com.quizlet.login.common.util.c.c(dBUser) || z) ? 0 : 1;
            io.ktor.client.plugins.api.d dVar = oVar.c;
            this.j = r7;
            this.k = 1;
            if (dVar.u(this.o, dBUser, r7, this) == aVar) {
                return aVar;
            }
            i = r7;
        } else {
            if (i2 != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            i = this.j;
            Z.e(obj);
        }
        if (i != 0) {
            oVar.f.t(oVar.w, dBUser);
            E.A(p0.j(oVar), null, null, new k(oVar, dBUser, null), 3);
        } else {
            oVar.getClass();
            E.A(p0.j(oVar), null, null, new l(oVar, dBUser, z, null), 3);
        }
        return Unit.a;
    }
}
