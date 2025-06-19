package com.quizlet.features.folders.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.S4;
import com.google.android.gms.internal.mlkit_vision_camera.H2;
import com.quizlet.features.folders.data.W0;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class Y implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ float c;
    public final /* synthetic */ int d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ InterfaceC4938g h;
    public final /* synthetic */ InterfaceC4938g i;

    public /* synthetic */ Y(com.quizlet.features.folders.data.U u, W0 w0, androidx.compose.ui.q qVar, androidx.compose.foundation.lazy.A a, float f, Function1 function1, Function1 function12, int i) {
        this.e = u;
        this.f = w0;
        this.b = qVar;
        this.g = a;
        this.c = f;
        this.h = function1;
        this.i = function12;
        this.d = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.d | 1);
                Function1 function1 = (Function1) this.h;
                Function1 function12 = (Function1) this.i;
                S4.b((com.quizlet.features.folders.data.U) this.e, (W0) this.f, this.b, (androidx.compose.foundation.lazy.A) this.g, this.c, function1, function12, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.d | 1);
                Function0 function0 = (Function0) this.h;
                Function0 function02 = (Function0) this.i;
                H2.a((com.quizlet.features.questiontypes.data.d) this.e, (DiagramData) this.f, this.b, this.c, (Function0) this.g, function0, function02, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ Y(com.quizlet.features.questiontypes.data.d dVar, DiagramData diagramData, androidx.compose.ui.q qVar, float f, Function0 function0, Function0 function02, Function0 function03, int i) {
        this.e = dVar;
        this.f = diagramData;
        this.b = qVar;
        this.c = f;
        this.g = function0;
        this.h = function02;
        this.i = function03;
        this.d = i;
    }
}
