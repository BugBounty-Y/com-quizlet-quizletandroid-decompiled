package com.quizlet.features.emailconfirmation.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3459g3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3754w6;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class e implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ InterfaceC4938g b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ InterfaceC4938g f;
    public final /* synthetic */ Object g;

    public /* synthetic */ e(r rVar, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, Function0 function03, boolean z, int i) {
        this.d = rVar;
        this.e = qVar;
        this.b = function0;
        this.f = function02;
        this.g = function03;
        this.c = z;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                Function0 function0 = (Function0) this.g;
                boolean z = this.c;
                q.b((r) this.d, (androidx.compose.ui.q) this.e, (Function0) this.b, (Function0) this.f, function0, z, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(3137);
                boolean z2 = this.c;
                com.quizlet.qutils.string.g gVar = (com.quizlet.qutils.string.g) this.g;
                AbstractC3459g3.a((com.quizlet.features.settings.data.models.b) this.d, (com.quizlet.assembly.compose.modals.x) this.e, (Function1) this.f, (Function0) this.b, z2, gVar, (InterfaceC0806l) obj, iH2);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(9);
                Function2 function2 = (Function2) this.g;
                androidx.compose.ui.q qVar = (androidx.compose.ui.q) this.e;
                AbstractC3754w6.a((com.quizlet.learn.checkpoint.data.d) this.d, this.c, (kotlin.jvm.functions.d) this.b, (kotlin.jvm.functions.c) this.f, function2, qVar, (InterfaceC0806l) obj, iH3);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ e(com.quizlet.features.settings.data.models.b bVar, com.quizlet.assembly.compose.modals.x xVar, Function1 function1, Function0 function0, boolean z, com.quizlet.qutils.string.g gVar, int i) {
        this.d = bVar;
        this.e = xVar;
        this.f = function1;
        this.b = function0;
        this.c = z;
        this.g = gVar;
    }

    public /* synthetic */ e(com.quizlet.learn.checkpoint.data.d dVar, boolean z, kotlin.jvm.functions.d dVar2, kotlin.jvm.functions.c cVar, Function2 function2, androidx.compose.ui.q qVar, int i) {
        this.d = dVar;
        this.c = z;
        this.b = dVar2;
        this.f = cVar;
        this.g = function2;
        this.e = qVar;
    }
}
