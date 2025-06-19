package com.quizlet.features.practicetest.detail;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3495m3;
import com.google.android.gms.internal.mlkit_vision_common.E;
import com.google.android.gms.internal.mlkit_vision_common.N3;
import com.google.android.gms.internal.mlkit_vision_common.r;
import com.quizlet.data.model.m2;
import com.quizlet.diagrams.ui.DiagramJSBridge;
import com.quizlet.features.setpage.termlist.data.p;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function2 {
    public final /* synthetic */ int a = 4;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ Object j;
    public final /* synthetic */ Object k;

    public /* synthetic */ c(m2 m2Var, Function0 function0, Function1 function1, Function1 function12, Function1 function13, Function1 function14, Function0 function02, Function0 function03, Function0 function04, com.quizlet.features.universaluploadflow.viewmodel.a aVar, int i) {
        this.g = m2Var;
        this.c = function0;
        this.b = function1;
        this.d = function12;
        this.e = function13;
        this.f = function14;
        this.h = function02;
        this.i = function03;
        this.j = function04;
        this.k = aVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(49);
                Function2 function2 = (Function2) this.j;
                com.quizlet.features.practicetest.detail.viewmodel.a aVar = (com.quizlet.features.practicetest.detail.viewmodel.a) this.k;
                W1.I(this.b, (Function0) this.c, (Function1) this.d, (kotlin.jvm.functions.d) this.h, (Function2) this.i, (Function1) this.e, (Function1) this.f, (Function1) this.g, function2, aVar, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                Function0 function0 = (Function0) this.j;
                Function0 function02 = (Function0) this.k;
                r.a((com.quizlet.features.setpage.header.data.d) this.d, (androidx.compose.ui.n) this.e, this.b, (Function0) this.c, (Function0) this.f, (Function0) this.g, (Function0) this.h, (Function0) this.i, function0, function02, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(65);
                DiagramJSBridge diagramJSBridge = (DiagramJSBridge) this.f;
                kotlin.jvm.functions.c cVar = (kotlin.jvm.functions.c) this.k;
                Function1 function1 = (Function1) this.d;
                E.b((p) this.e, diagramJSBridge, (androidx.compose.ui.n) this.g, (com.quizlet.features.setpage.termlist.ui.c) this.j, this.b, (Function0) this.c, (Function2) this.i, (kotlin.jvm.functions.d) this.h, cVar, function1, (InterfaceC0806l) obj, iH3);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(1);
                com.quizlet.features.settings.data.models.h hVar = (com.quizlet.features.settings.data.models.h) this.f;
                Function1 function12 = (Function1) this.e;
                com.quizlet.assembly.compose.input.n nVar = (com.quizlet.assembly.compose.input.n) this.k;
                AbstractC3495m3.a(hVar, (q) this.g, (com.quizlet.features.settings.data.states.h) this.c, (String) this.h, this.b, (String) this.i, (Function1) this.d, (String) this.j, function12, nVar, (InterfaceC0806l) obj, iH4);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(1769521);
                m2 m2Var = (m2) this.g;
                Function0 function03 = (Function0) this.j;
                com.quizlet.features.universaluploadflow.viewmodel.a aVar2 = (com.quizlet.features.universaluploadflow.viewmodel.a) this.k;
                N3.d(m2Var, (Function0) this.c, this.b, (Function1) this.d, (Function1) this.e, (Function1) this.f, (Function0) this.h, (Function0) this.i, function03, aVar2, (InterfaceC0806l) obj, iH5);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ c(com.quizlet.features.setpage.header.data.d dVar, androidx.compose.ui.n nVar, Function1 function1, Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function0 function05, Function0 function06, Function0 function07, int i) {
        this.d = dVar;
        this.e = nVar;
        this.b = function1;
        this.c = function0;
        this.f = function02;
        this.g = function03;
        this.h = function04;
        this.i = function05;
        this.j = function06;
        this.k = function07;
    }

    public /* synthetic */ c(p pVar, DiagramJSBridge diagramJSBridge, androidx.compose.ui.n nVar, com.quizlet.features.setpage.termlist.ui.c cVar, Function1 function1, Function0 function0, Function2 function2, kotlin.jvm.functions.d dVar, kotlin.jvm.functions.c cVar2, Function1 function12, int i) {
        this.e = pVar;
        this.f = diagramJSBridge;
        this.g = nVar;
        this.j = cVar;
        this.b = function1;
        this.c = function0;
        this.i = function2;
        this.h = dVar;
        this.k = cVar2;
        this.d = function12;
    }

    public /* synthetic */ c(com.quizlet.features.settings.data.models.h hVar, q qVar, com.quizlet.features.settings.data.states.h hVar2, String str, Function1 function1, String str2, Function1 function12, String str3, Function1 function13, com.quizlet.assembly.compose.input.n nVar, int i) {
        this.f = hVar;
        this.g = qVar;
        this.c = hVar2;
        this.h = str;
        this.b = function1;
        this.i = str2;
        this.d = function12;
        this.j = str3;
        this.e = function13;
        this.k = nVar;
    }

    public /* synthetic */ c(Function1 function1, Function0 function0, Function1 function12, kotlin.jvm.functions.d dVar, Function2 function2, Function1 function13, Function1 function14, Function1 function15, Function2 function22, com.quizlet.features.practicetest.detail.viewmodel.a aVar, int i) {
        this.b = function1;
        this.c = function0;
        this.d = function12;
        this.h = dVar;
        this.i = function2;
        this.e = function13;
        this.f = function14;
        this.g = function15;
        this.j = function22;
        this.k = aVar;
    }
}
