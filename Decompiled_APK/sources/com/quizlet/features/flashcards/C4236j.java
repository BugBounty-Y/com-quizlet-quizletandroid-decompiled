package com.quizlet.features.flashcards;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3119d0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3348i;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3581b0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3625g4;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.flashcards.j, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4236j implements Function2 {
    public final /* synthetic */ int a = 3;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ InterfaceC4938g c;
    public final /* synthetic */ Function1 d;
    public final /* synthetic */ InterfaceC4938g e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ InterfaceC4938g g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;

    public /* synthetic */ C4236j(com.quizlet.login.signup.data.r rVar, kotlin.jvm.functions.d dVar, Function0 function0, Function0 function02, Function0 function03, Function1 function1, Function1 function12, androidx.compose.ui.q qVar, int i) {
        this.f = rVar;
        this.c = dVar;
        this.b = function0;
        this.g = function02;
        this.h = function03;
        this.d = function1;
        this.e = function12;
        this.i = qVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(7);
                S s = (S) this.h;
                com.quizlet.features.flashcards.autoplay.o oVar = (com.quizlet.features.flashcards.autoplay.o) this.i;
                AbstractC3119d0.c(this.b, this.d, (Function2) this.c, (Function1) this.e, (Function1) this.f, (Function2) this.g, s, oVar, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(221575);
                kotlin.jvm.functions.d dVar = (kotlin.jvm.functions.d) this.h;
                com.quizlet.features.notes.upload.viewmodels.k kVar = (com.quizlet.features.notes.upload.viewmodels.k) this.i;
                AbstractC3348i.d(this.b, (Function0) this.e, (Function2) this.c, (Function0) this.f, this.d, (kotlin.jvm.functions.c) this.g, dVar, kVar, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(1);
                Function0 function0 = (Function0) this.h;
                com.quizlet.login.parentemail.viewmodel.a aVar = (com.quizlet.login.parentemail.viewmodel.a) this.i;
                AbstractC3581b0.b(this.b, this.d, (Function0) this.f, (Function0) this.c, (Function1) this.e, (Function0) this.g, function0, aVar, (InterfaceC0806l) obj, iH3);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(1);
                Function1 function1 = (Function1) this.e;
                androidx.compose.ui.q qVar = (androidx.compose.ui.q) this.i;
                AbstractC3625g4.a((com.quizlet.login.signup.data.r) this.f, (kotlin.jvm.functions.d) this.c, this.b, (Function0) this.g, (Function0) this.h, this.d, function1, qVar, (InterfaceC0806l) obj, iH4);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(1);
                Function1 function12 = (Function1) this.e;
                androidx.compose.ui.n nVar = (androidx.compose.ui.n) this.i;
                com.google.mlkit.common.model.a.d((com.quizlet.quizletandroid.ui.subject.viewmodel.h) this.f, this.b, (Function0) this.g, (Function0) this.h, (Function2) this.c, this.d, function12, nVar, (InterfaceC0806l) obj, iH5);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ C4236j(com.quizlet.quizletandroid.ui.subject.viewmodel.h hVar, Function0 function0, Function0 function02, Function0 function03, Function2 function2, Function1 function1, Function1 function12, androidx.compose.ui.n nVar, int i) {
        this.f = hVar;
        this.b = function0;
        this.g = function02;
        this.h = function03;
        this.c = function2;
        this.d = function1;
        this.e = function12;
        this.i = nVar;
    }

    public /* synthetic */ C4236j(Function0 function0, Function0 function02, Function2 function2, Function0 function03, Function1 function1, kotlin.jvm.functions.c cVar, kotlin.jvm.functions.d dVar, com.quizlet.features.notes.upload.viewmodels.k kVar, int i) {
        this.b = function0;
        this.e = function02;
        this.c = function2;
        this.f = function03;
        this.d = function1;
        this.g = cVar;
        this.h = dVar;
        this.i = kVar;
    }

    public /* synthetic */ C4236j(Function0 function0, Function1 function1, Function0 function02, Function0 function03, Function1 function12, Function0 function04, Function0 function05, com.quizlet.login.parentemail.viewmodel.a aVar, int i) {
        this.b = function0;
        this.d = function1;
        this.f = function02;
        this.c = function03;
        this.e = function12;
        this.g = function04;
        this.h = function05;
        this.i = aVar;
    }

    public /* synthetic */ C4236j(Function0 function0, Function1 function1, Function2 function2, Function1 function12, Function1 function13, Function2 function22, S s, com.quizlet.features.flashcards.autoplay.o oVar, int i) {
        this.b = function0;
        this.d = function1;
        this.c = function2;
        this.e = function12;
        this.f = function13;
        this.g = function22;
        this.h = s;
        this.i = oVar;
    }
}
