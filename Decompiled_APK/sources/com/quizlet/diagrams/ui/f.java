package com.quizlet.diagrams.ui;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3134e6;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3515q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L6;
import com.quizlet.data.model.A0;
import com.quizlet.learn.settings.data.WrittenQuestionGradingOption;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class f implements Function2 {
    public final /* synthetic */ int a = 3;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ int c;
    public final /* synthetic */ InterfaceC4938g d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;

    public /* synthetic */ f(n nVar, boolean z, androidx.compose.ui.focus.h hVar, int i, Function1 function1, Function0 function0, Function1 function12, int i2) {
        this.e = nVar;
        this.b = z;
        this.f = hVar;
        this.c = i;
        this.g = function1;
        this.d = function0;
        this.h = function12;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.c | 1);
                Function0 function0 = (Function0) this.d;
                Function0 function02 = (Function0) this.h;
                L6.b((String) this.e, (DiagramJSBridge) this.f, (q) this.g, this.b, function0, function02, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                Function0 function03 = (Function0) this.d;
                Function1 function1 = (Function1) this.h;
                L4.a((n) this.e, this.b, (androidx.compose.ui.focus.h) this.f, this.c, (Function1) this.g, function03, function1, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(27697);
                Function0 function04 = (Function0) this.h;
                AbstractC3134e6.b((com.quizlet.features.infra.folder.menu.screenstates.d) this.e, this.b, (q) this.g, (Function0) this.d, (Function1) this.f, function04, (InterfaceC0806l) obj, iH3, this.c);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(this.c | 1);
                A0 a0 = (A0) this.h;
                boolean z = this.b;
                AbstractC3515q.c((androidx.compose.ui.graphics.painter.b) this.f, (String) this.e, (q) this.g, (Function0) this.d, a0, z, (InterfaceC0806l) obj, iH4);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.c | 1);
                Function1 function12 = (Function1) this.h;
                q qVar = (q) this.g;
                E6.g((kotlinx.collections.immutable.c) this.e, (WrittenQuestionGradingOption) this.f, this.b, (Function1) this.d, function12, qVar, (InterfaceC0806l) obj, iH5);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ f(androidx.compose.ui.graphics.painter.b bVar, String str, q qVar, Function0 function0, A0 a0, boolean z, int i) {
        this.f = bVar;
        this.e = str;
        this.g = qVar;
        this.d = function0;
        this.h = a0;
        this.b = z;
        this.c = i;
    }

    public /* synthetic */ f(com.quizlet.features.infra.folder.menu.screenstates.d dVar, boolean z, q qVar, Function0 function0, Function1 function1, Function0 function02, int i, int i2) {
        this.e = dVar;
        this.b = z;
        this.g = qVar;
        this.d = function0;
        this.f = function1;
        this.h = function02;
        this.c = i2;
    }

    public /* synthetic */ f(String str, DiagramJSBridge diagramJSBridge, q qVar, boolean z, Function0 function0, Function0 function02, int i) {
        this.e = str;
        this.f = diagramJSBridge;
        this.g = qVar;
        this.b = z;
        this.d = function0;
        this.h = function02;
        this.c = i;
    }

    public /* synthetic */ f(kotlinx.collections.immutable.c cVar, WrittenQuestionGradingOption writtenQuestionGradingOption, boolean z, Function1 function1, Function1 function12, q qVar, int i) {
        this.e = cVar;
        this.f = writtenQuestionGradingOption;
        this.b = z;
        this.d = function1;
        this.h = function12;
        this.g = qVar;
        this.c = i;
    }
}
