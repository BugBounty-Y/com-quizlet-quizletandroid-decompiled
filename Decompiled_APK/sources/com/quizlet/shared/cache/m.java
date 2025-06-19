package com.quizlet.shared.cache;

import androidx.compose.ui.node.B;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3410x2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.H;
import com.google.android.gms.measurement.internal.J;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.K;

/* loaded from: classes3.dex */
public final class m extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ kotlinx.coroutines.scheduling.e b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ m(kotlinx.coroutines.scheduling.e eVar, int i) {
        super(2);
        this.a = i;
        this.b = eVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                org.koin.core.scope.a aVar = (org.koin.core.scope.a) obj;
                j jVar = (j) aVar.a(null, B.q(aVar, "$this$single", (org.koin.core.parameter.a) obj2, "it", j.class), null);
                return new com.quizlet.shared.repository.folders.d(H.a(jVar.a, c.c), this.b);
            default:
                org.koin.core.scope.a aVar2 = (org.koin.core.scope.a) obj;
                t tVar = (t) aVar2.a(null, B.q(aVar2, "$this$factory", (org.koin.core.parameter.a) obj2, "it", t.class), null);
                kotlinx.serialization.json.c cVar = (kotlinx.serialization.json.c) aVar2.a(null, K.a(kotlinx.serialization.json.c.class), AbstractC3410x2.b("data-layer-json"));
                return new s(new J(tVar.a, tVar.b, this.b), this.b, new com.quizlet.remote.model.set.d(new com.quizlet.quizletandroid.k(cVar), new com.quizlet.quizletandroid.ui.login.h(cVar)), new com.quizlet.quizletandroid.ui.folder.logging.a(4), new com.quizlet.quizletandroid.ui.common.images.capture.b(4));
        }
    }
}
