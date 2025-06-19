package androidx.activity.compose;

import androidx.glance.appwidget.protobuf.Z;
import androidx.paging.I;
import io.ktor.client.plugins.AbstractC4857d;
import kotlin.Unit;
import kotlin.jvm.internal.F;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes.dex */
public final class p extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int j;
    public /* synthetic */ Object k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ p(int i, int i2, kotlin.coroutines.h hVar) {
        super(i, hVar);
        this.j = i2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.j) {
            case 0:
                return new p((F) this.k, (kotlin.coroutines.h) obj3, 0).invokeSuspend(Unit.a);
            case 1:
                return new p((I) this.k, (kotlin.coroutines.h) obj3, 1).invokeSuspend(Unit.a);
            case 2:
                return new p((com.quizlet.features.setpage.terms.viewmodel.c) this.k, (kotlin.coroutines.h) obj3, 2).invokeSuspend(Unit.a);
            case 3:
                return new p((com.quizlet.features.setpage.viewmodel.selectedtermsmode.b) this.k, (kotlin.coroutines.h) obj3, 3).invokeSuspend(Unit.a);
            case 4:
                return new p((com.quizlet.data.repository.metering.j) this.k, (kotlin.coroutines.h) obj3, 4).invokeSuspend(Unit.a);
            case 5:
                p pVar = new p(3, 5, (kotlin.coroutines.h) obj3);
                pVar.k = (com.quizlet.features.infra.studysetting.managers.a) obj2;
                return pVar.invokeSuspend(Unit.a);
            default:
                p pVar2 = new p(3, 6, (kotlin.coroutines.h) obj3);
                pVar2.k = (io.ktor.client.request.c) obj;
                pVar2.invokeSuspend(Unit.a);
                return null;
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        switch (this.j) {
            case 0:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                ((F) this.k).a = true;
                return Unit.a;
            case 1:
                kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                ((I) this.k).getClass();
                return Unit.a;
            case 2:
                kotlin.coroutines.intrinsics.a aVar3 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                ((com.quizlet.features.setpage.terms.viewmodel.c) this.k).g.b(false);
                return Unit.a;
            case 3:
                kotlin.coroutines.intrinsics.a aVar4 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                s0 s0Var = ((com.quizlet.features.setpage.viewmodel.selectedtermsmode.b) this.k).g;
                do {
                    value = s0Var.getValue();
                } while (!s0Var.k(value, com.quizlet.features.setpage.terms.b.a));
                return Unit.a;
            case 4:
                kotlin.coroutines.intrinsics.a aVar5 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                com.quizlet.data.repository.metering.j jVar = (com.quizlet.data.repository.metering.j) this.k;
                com.quizlet.features.infra.studysetting.datasource.a aVar6 = (com.quizlet.features.infra.studysetting.datasource.a) jVar.c;
                if (aVar6 != null) {
                    aVar6.g();
                }
                com.quizlet.features.infra.studysetting.datasource.a aVar7 = (com.quizlet.features.infra.studysetting.datasource.a) jVar.d;
                if (aVar7 != null) {
                    aVar7.g();
                }
                return Unit.a;
            case 5:
                kotlin.coroutines.intrinsics.a aVar8 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                return ((com.quizlet.features.infra.studysetting.managers.a) this.k).c();
            default:
                kotlin.coroutines.intrinsics.a aVar9 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                if (((io.ktor.client.request.c) this.k).f.d(AbstractC4857d.a) == null) {
                    return null;
                }
                throw new ClassCastException();
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ p(Object obj, kotlin.coroutines.h hVar, int i) {
        super(3, hVar);
        this.j = i;
        this.k = obj;
    }
}
