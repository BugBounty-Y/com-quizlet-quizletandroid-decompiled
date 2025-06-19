package com.quizlet.features.flashcards;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3119d0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.flashcards.i, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4235i implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ Function0 d;
    public final /* synthetic */ Function0 e;
    public final /* synthetic */ Function0 f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Function0 h;
    public final /* synthetic */ Function0 i;
    public final /* synthetic */ Object j;
    public final /* synthetic */ Object k;
    public final /* synthetic */ Object l;

    public /* synthetic */ C4235i(com.quizlet.features.flashcards.data.o oVar, Function1 function1, Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function0 function05, Function0 function06, Function1 function12, com.quizlet.ui.compose.N n, androidx.compose.ui.q qVar, int i) {
        this.j = oVar;
        this.b = function1;
        this.c = function0;
        this.d = function02;
        this.e = function03;
        this.f = function04;
        this.h = function05;
        this.i = function06;
        this.g = function12;
        this.k = n;
        this.l = qVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                com.quizlet.features.flashcards.data.o oVar = (com.quizlet.features.flashcards.data.o) this.j;
                com.quizlet.ui.compose.N n = (com.quizlet.ui.compose.N) this.k;
                androidx.compose.ui.q qVar = (androidx.compose.ui.q) this.l;
                AbstractC3119d0.a(oVar, this.b, this.c, this.d, this.e, this.f, this.h, this.i, (Function1) this.g, n, qVar, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                com.quizlet.login.intro.viewmodel.a aVar = (com.quizlet.login.intro.viewmodel.a) this.k;
                com.quizlet.features.infra.google.e eVar = (com.quizlet.features.infra.google.e) this.l;
                com.google.android.gms.internal.mlkit_vision_document_scanner.L.e(this.b, this.c, this.d, this.e, this.f, (Function1) this.g, (Function2) this.j, this.h, this.i, aVar, eVar, (InterfaceC0806l) obj, iH2);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(1);
                com.quizlet.features.infra.google.e eVar2 = (com.quizlet.features.infra.google.e) this.k;
                com.quizlet.data.interactor.achievements.f fVar = (com.quizlet.data.interactor.achievements.f) this.l;
                com.google.android.gms.internal.mlkit_vision_document_scanner.P.d(this.c, this.d, this.e, this.f, this.h, this.i, (Function2) this.j, this.b, (com.quizlet.login.login.viewmodel.a) this.g, eVar2, fVar, (InterfaceC0806l) obj, iH3);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ C4235i(Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function0 function05, Function0 function06, Function2 function2, Function1 function1, com.quizlet.login.login.viewmodel.a aVar, com.quizlet.features.infra.google.e eVar, com.quizlet.data.interactor.achievements.f fVar, int i) {
        this.c = function0;
        this.d = function02;
        this.e = function03;
        this.f = function04;
        this.h = function05;
        this.i = function06;
        this.j = function2;
        this.b = function1;
        this.g = aVar;
        this.k = eVar;
        this.l = fVar;
    }

    public /* synthetic */ C4235i(Function1 function1, Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function1 function12, Function2 function2, Function0 function05, Function0 function06, com.quizlet.login.intro.viewmodel.a aVar, com.quizlet.features.infra.google.e eVar, int i) {
        this.b = function1;
        this.c = function0;
        this.d = function02;
        this.e = function03;
        this.f = function04;
        this.g = function12;
        this.j = function2;
        this.h = function05;
        this.i = function06;
        this.k = aVar;
        this.l = eVar;
    }
}
