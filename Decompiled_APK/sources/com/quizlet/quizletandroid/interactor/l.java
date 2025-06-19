package com.quizlet.quizletandroid.interactor;

import androidx.camera.camera2.internal.T;
import androidx.glance.appwidget.protobuf.Z;
import androidx.paging.C1319i;
import com.google.android.gms.internal.mlkit_vision_camera.H1;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.generated.enums.G1;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;
import kotlinx.coroutines.flow.V;
import kotlinx.coroutines.flow.internal.AbstractC4994b;
import kotlinx.coroutines.flow.internal.B;
import kotlinx.coroutines.z0;

/* loaded from: classes3.dex */
public final class l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public J j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ m m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(m mVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        l lVar = new l(this.m, hVar);
        lVar.l = obj;
        return lVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((l) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        InterfaceC5002j interfaceC5002j;
        J j;
        int i = 3;
        int i2 = 21;
        int i3 = 0;
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i4 = this.k;
        m mVar = this.m;
        if (i4 == 0) {
            Z.e(obj);
            interfaceC5002j = (InterfaceC5002j) this.l;
            j = new J();
            j jVar = new j(j, mVar, null);
            this.l = interfaceC5002j;
            this.j = j;
            this.k = 1;
            z0 z0Var = new z0(getContext(), this, i3);
            Object objC = H1.c(z0Var, true, z0Var, jVar);
            if (objC == obj2) {
                Intrinsics.checkNotNullParameter(this, "frame");
            }
            if (objC == obj2) {
                return obj2;
            }
        } else {
            if (i4 != 1) {
                if (i4 != 2) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
                return Unit.a;
            }
            j = this.j;
            interfaceC5002j = (InterfaceC5002j) this.l;
            Z.e(obj);
        }
        J j2 = j;
        InterfaceC5002j interfaceC5002j2 = interfaceC5002j;
        mVar.getClass();
        com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.STUDY_SET);
        Relationship<DBStudySet, DBUser> relationship = DBStudySetFields.CREATOR;
        long j3 = mVar.a;
        bVar.b(Long.valueOf(j3), relationship);
        bVar.e(relationship);
        com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
        com.quizlet.infra.legacysyncengine.net.c cVar = mVar.b;
        cVar.getClass();
        Set set = com.quizlet.infra.legacysyncengine.net.c.e;
        com.jakewharton.rxbinding4.a aVar = new com.jakewharton.rxbinding4.a(new T(cVar, aVarA, set, i2), i);
        Intrinsics.checkNotNullExpressionValue(aVar, "fetchAll(...)");
        f fVar = new f(K1.f(aVar), mVar, i3);
        com.quizlet.infra.legacysyncengine.orm.b bVar2 = new com.quizlet.infra.legacysyncengine.orm.b(Models.SESSION);
        bVar2.b(Long.valueOf(j3), DBSessionFields.PERSON);
        bVar2.b(Long.valueOf(G1.SET.b()), DBSessionFields.ITEM_TYPE);
        bVar2.e(DBSessionFields.STUDYABLE, relationship);
        com.quizlet.infra.legacysyncengine.orm.query.a aVarA2 = bVar2.a();
        cVar.getClass();
        com.jakewharton.rxbinding4.a aVar2 = new com.jakewharton.rxbinding4.a(new T(cVar, aVarA2, set, i2), i);
        Intrinsics.checkNotNullExpressionValue(aVar2, "fetchAll(...)");
        f fVar2 = new f(K1.f(aVar2), mVar, 1);
        k kVar = new k(mVar, j2, interfaceC5002j2, null, 0);
        this.l = null;
        this.j = null;
        this.k = 2;
        Object objA = AbstractC4994b.a(this, V.a, new C1319i(kVar, (kotlin.coroutines.h) null), B.a, new InterfaceC4992i[]{fVar, fVar2});
        if (objA != obj2) {
            objA = Unit.a;
        }
        if (objA != obj2) {
            objA = Unit.a;
        }
        if (objA == obj2) {
            return obj2;
        }
        return Unit.a;
    }
}
