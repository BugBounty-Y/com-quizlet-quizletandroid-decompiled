package com.quizlet.shared.repository.di;

import androidx.compose.ui.node.B;
import com.quizlet.shared.persistence.studiableMetadata.f;
import com.quizlet.shared.quizletapi.studynotes.d;
import com.quizlet.shared.quizletapi.studynotes.e;
import com.quizlet.shared.quizletapi.studynotes.g;
import com.quizlet.shared.repository.h;
import com.quizlet.shared.repository.i;
import com.quizlet.shared.repository.j;
import com.quizlet.shared.repository.studynotes.k;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.r;
import org.koin.core.error.NoBeanDefFoundException;

/* loaded from: classes3.dex */
public final class a extends r implements Function2 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) throws NoBeanDefFoundException {
        switch (this.a) {
            case 0:
                org.koin.core.scope.a aVar = (org.koin.core.scope.a) obj;
                com.quizlet.shared.quizletapi.grading.a service = (com.quizlet.shared.quizletapi.grading.a) aVar.a(null, B.q(aVar, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.quizletapi.grading.a.class), null);
                Intrinsics.checkNotNullParameter(service, "service");
                return new h(service);
            case 1:
                org.koin.core.scope.a aVar2 = (org.koin.core.scope.a) obj;
                return new j((com.quizlet.shared.quizletapi.studiableMetadata.a) aVar2.a(null, B.q(aVar2, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.quizletapi.studiableMetadata.a.class), null), (f) aVar2.a(null, K.a(f.class), null));
            case 2:
                org.koin.core.scope.a aVar3 = (org.koin.core.scope.a) obj;
                com.quizlet.shared.quizletapi.srs.a service2 = (com.quizlet.shared.quizletapi.srs.a) aVar3.a(null, B.q(aVar3, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.quizletapi.srs.a.class), null);
                Intrinsics.checkNotNullParameter(service2, "service");
                return new i(service2);
            case 3:
                org.koin.core.scope.a aVar4 = (org.koin.core.scope.a) obj;
                d service3 = (d) aVar4.a(null, B.q(aVar4, "$this$factory", (org.koin.core.parameter.a) obj2, "it", d.class), null);
                Intrinsics.checkNotNullParameter(service3, "service");
                return new com.quizlet.shared.repository.studynotes.a(service3);
            case 4:
                org.koin.core.scope.a aVar5 = (org.koin.core.scope.a) obj;
                com.quizlet.shared.quizletapi.studynotes.f service4 = (com.quizlet.shared.quizletapi.studynotes.f) aVar5.a(null, B.q(aVar5, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.quizletapi.studynotes.f.class), null);
                Intrinsics.checkNotNullParameter(service4, "service");
                return new com.quizlet.shared.repository.studynotes.j(service4);
            case 5:
                org.koin.core.scope.a aVar6 = (org.koin.core.scope.a) obj;
                e service5 = (e) aVar6.a(null, B.q(aVar6, "$this$factory", (org.koin.core.parameter.a) obj2, "it", e.class), null);
                Intrinsics.checkNotNullParameter(service5, "service");
                return new com.quizlet.shared.repository.studynotes.i(service5);
            case 6:
                org.koin.core.scope.a aVar7 = (org.koin.core.scope.a) obj;
                g service6 = (g) aVar7.a(null, B.q(aVar7, "$this$factory", (org.koin.core.parameter.a) obj2, "it", g.class), null);
                Intrinsics.checkNotNullParameter(service6, "service");
                return new k(service6);
            case 7:
                org.koin.core.scope.a aVar8 = (org.koin.core.scope.a) obj;
                com.quizlet.shared.quizletapi.studyset.a service7 = (com.quizlet.shared.quizletapi.studyset.a) aVar8.a(null, B.q(aVar8, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.quizletapi.studyset.a.class), null);
                Intrinsics.checkNotNullParameter(service7, "service");
                return new com.quizlet.shared.repository.k(service7);
            default:
                org.koin.core.scope.a aVar9 = (org.koin.core.scope.a) obj;
                return new com.quizlet.shared.repository.eligibility.b((com.quizlet.shared.quizletapi.eligibility.a) aVar9.a(null, B.q(aVar9, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.quizletapi.eligibility.a.class), null));
        }
    }
}
