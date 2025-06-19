package com.quizlet.shared.quizletapi.di;

import androidx.compose.ui.node.B;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3410x2;
import com.quizlet.shared.quizletapi.eligibility.d;
import com.quizlet.shared.quizletapi.studynotes.i;
import com.quizlet.shared.quizletapi.studynotes.k;
import com.quizlet.shared.quizletapi.studynotes.m;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.r;
import org.koin.core.error.NoBeanDefFoundException;

/* loaded from: classes3.dex */
public final class a extends r implements Function2 {
    public static final a b = new a(2, 0);
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
                org.koin.core.scope.a single = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it2 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(single, "$this$single");
                Intrinsics.checkNotNullParameter(it2, "it");
                String str = (String) single.b(null, K.a(String.class), AbstractC3410x2.b("QUIZLET_API_BASE_URL_OVERRIDE"));
                if (str == null) {
                    str = "api.quizlet.com";
                }
                return new com.quizlet.shared.quizletapi.b(str);
            case 1:
                org.koin.core.scope.a aVar = (org.koin.core.scope.a) obj;
                Object objA = aVar.a(null, B.q(aVar, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.remote.kmp.a.class), null);
                return new i((com.quizlet.remote.kmp.a) objA, (kotlinx.serialization.json.c) aVar.a(null, K.a(kotlinx.serialization.json.c.class), null), (com.quizlet.shared.quizletapi.b) aVar.a(null, K.a(com.quizlet.shared.quizletapi.b.class), null));
            case 2:
                org.koin.core.scope.a aVar2 = (org.koin.core.scope.a) obj;
                Object objA2 = aVar2.a(null, B.q(aVar2, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.remote.kmp.a.class), null);
                return new m((com.quizlet.remote.kmp.a) objA2, (kotlinx.serialization.json.c) aVar2.a(null, K.a(kotlinx.serialization.json.c.class), null), (com.quizlet.shared.quizletapi.b) aVar2.a(null, K.a(com.quizlet.shared.quizletapi.b.class), null));
            case 3:
                org.koin.core.scope.a aVar3 = (org.koin.core.scope.a) obj;
                Object objA3 = aVar3.a(null, B.q(aVar3, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.remote.kmp.a.class), null);
                return new d((com.quizlet.remote.kmp.a) objA3, (kotlinx.serialization.json.c) aVar3.a(null, K.a(kotlinx.serialization.json.c.class), null), (com.quizlet.shared.quizletapi.b) aVar3.a(null, K.a(com.quizlet.shared.quizletapi.b.class), null));
            case 4:
                org.koin.core.scope.a aVar4 = (org.koin.core.scope.a) obj;
                Object objA4 = aVar4.a(null, B.q(aVar4, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.remote.kmp.a.class), null);
                return new com.quizlet.shared.quizletapi.studiableMetadata.d((com.quizlet.remote.kmp.a) objA4, (kotlinx.serialization.json.c) aVar4.a(null, K.a(kotlinx.serialization.json.c.class), null), (com.quizlet.shared.quizletapi.b) aVar4.a(null, K.a(com.quizlet.shared.quizletapi.b.class), null));
            case 5:
                org.koin.core.scope.a aVar5 = (org.koin.core.scope.a) obj;
                Object objA5 = aVar5.a(null, B.q(aVar5, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.remote.kmp.a.class), null);
                return new com.quizlet.shared.quizletapi.grading.d((com.quizlet.remote.kmp.a) objA5, (kotlinx.serialization.json.c) aVar5.a(null, K.a(kotlinx.serialization.json.c.class), null), (com.quizlet.shared.quizletapi.b) aVar5.a(null, K.a(com.quizlet.shared.quizletapi.b.class), null));
            case 6:
                org.koin.core.scope.a aVar6 = (org.koin.core.scope.a) obj;
                Object objA6 = aVar6.a(null, B.q(aVar6, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.remote.kmp.a.class), null);
                return new com.quizlet.shared.quizletapi.srs.d((com.quizlet.remote.kmp.a) objA6, (kotlinx.serialization.json.c) aVar6.a(null, K.a(kotlinx.serialization.json.c.class), null), (com.quizlet.shared.quizletapi.b) aVar6.a(null, K.a(com.quizlet.shared.quizletapi.b.class), null));
            case 7:
                org.koin.core.scope.a aVar7 = (org.koin.core.scope.a) obj;
                Object objA7 = aVar7.a(null, B.q(aVar7, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.remote.kmp.a.class), null);
                return new com.quizlet.shared.quizletapi.studyset.d((com.quizlet.remote.kmp.a) objA7, (kotlinx.serialization.json.c) aVar7.a(null, K.a(kotlinx.serialization.json.c.class), null), (com.quizlet.shared.quizletapi.b) aVar7.a(null, K.a(com.quizlet.shared.quizletapi.b.class), null));
            case 8:
                org.koin.core.scope.a aVar8 = (org.koin.core.scope.a) obj;
                Object objA8 = aVar8.a(null, B.q(aVar8, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.remote.kmp.a.class), null);
                return new com.quizlet.shared.quizletapi.studynotes.c((com.quizlet.remote.kmp.a) objA8, (kotlinx.serialization.json.c) aVar8.a(null, K.a(kotlinx.serialization.json.c.class), null), (com.quizlet.shared.quizletapi.b) aVar8.a(null, K.a(com.quizlet.shared.quizletapi.b.class), null));
            case 9:
                org.koin.core.scope.a aVar9 = (org.koin.core.scope.a) obj;
                Object objA9 = aVar9.a(null, B.q(aVar9, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.remote.kmp.a.class), null);
                return new com.quizlet.shared.quizletapi.folderstudymaterials.d((com.quizlet.remote.kmp.a) objA9, (kotlinx.serialization.json.c) aVar9.a(null, K.a(kotlinx.serialization.json.c.class), null), (com.quizlet.shared.quizletapi.b) aVar9.a(null, K.a(com.quizlet.shared.quizletapi.b.class), null));
            case 10:
                org.koin.core.scope.a aVar10 = (org.koin.core.scope.a) obj;
                Object objA10 = aVar10.a(null, B.q(aVar10, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.remote.kmp.a.class), null);
                return new com.quizlet.shared.quizletapi.folders.a((com.quizlet.remote.kmp.a) objA10, (kotlinx.serialization.json.c) aVar10.a(null, K.a(kotlinx.serialization.json.c.class), null), (com.quizlet.shared.quizletapi.b) aVar10.a(null, K.a(com.quizlet.shared.quizletapi.b.class), null));
            case 11:
                org.koin.core.scope.a aVar11 = (org.koin.core.scope.a) obj;
                Object objA11 = aVar11.a(null, B.q(aVar11, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.remote.kmp.a.class), null);
                return new com.quizlet.shared.quizletapi.folderstudymaterials.a((com.quizlet.remote.kmp.a) objA11, (kotlinx.serialization.json.c) aVar11.a(null, K.a(kotlinx.serialization.json.c.class), null), (com.quizlet.shared.quizletapi.b) aVar11.a(null, K.a(com.quizlet.shared.quizletapi.b.class), null));
            default:
                org.koin.core.scope.a aVar12 = (org.koin.core.scope.a) obj;
                Object objA12 = aVar12.a(null, B.q(aVar12, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.remote.kmp.a.class), null);
                return new k((com.quizlet.remote.kmp.a) objA12, (kotlinx.serialization.json.c) aVar12.a(null, K.a(kotlinx.serialization.json.c.class), null), (com.quizlet.shared.quizletapi.b) aVar12.a(null, K.a(com.quizlet.shared.quizletapi.b.class), null));
        }
    }
}
