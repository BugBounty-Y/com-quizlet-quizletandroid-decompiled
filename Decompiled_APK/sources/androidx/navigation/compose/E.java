package androidx.navigation.compose;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0995g;
import com.google.android.gms.internal.mlkit_vision_barcode.B5;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.google.android.gms.internal.mlkit_vision_camera.Q1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3465h3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3667l6;
import com.quizlet.generated.enums.y1;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final /* synthetic */ class E implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ InterfaceC4938g f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ Object j;

    public /* synthetic */ E(com.quizlet.assembly.compose.menu.s sVar, com.quizlet.features.folders.menu.u uVar, String str, y1 y1Var, Function2 function2, Function1 function1, Function0 function0, androidx.compose.ui.q qVar, int i) {
        this.a = 2;
        this.c = sVar;
        this.d = uVar;
        this.e = str;
        this.g = y1Var;
        this.h = function2;
        this.f = function1;
        this.i = function0;
        this.j = qVar;
        this.b = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.b | 1);
                Function1 function1 = (Function1) this.i;
                Function1 function12 = (Function1) this.j;
                Q1.a((androidx.navigation.H) this.c, (androidx.compose.ui.n) this.d, (androidx.compose.ui.i) this.e, (Function1) this.f, (Function1) this.g, (Function1) this.h, function1, function12, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.b | 1);
                C0995g c0995g = (C0995g) this.c;
                com.quizlet.assembly.compose.toasts.g gVar = (com.quizlet.assembly.compose.toasts.g) this.i;
                com.quizlet.assembly.compose.toasts.f fVar = (com.quizlet.assembly.compose.toasts.f) this.j;
                AbstractC3667l6.a(c0995g, (androidx.compose.ui.q) this.d, (String) this.e, (Function0) this.f, (Function0) this.g, (Function0) this.h, gVar, fVar, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.b | 1);
                Function0 function0 = (Function0) this.i;
                androidx.compose.ui.q qVar = (androidx.compose.ui.q) this.j;
                T4.b((com.quizlet.assembly.compose.menu.s) this.c, (com.quizlet.features.folders.menu.u) this.d, (String) this.e, (y1) this.g, (Function2) this.h, (Function1) this.f, function0, qVar, (InterfaceC0806l) obj, iH3);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(this.b | 1);
                com.quizlet.data.interactor.folderwithcreator.m mVar = (com.quizlet.data.interactor.folderwithcreator.m) this.d;
                com.quizlet.features.infra.logout.composables.a aVar = (com.quizlet.features.infra.logout.composables.a) this.e;
                Function2 function2 = (Function2) this.j;
                Function1 function13 = (Function1) this.f;
                AbstractC3465h3.b((com.quizlet.features.settings.data.models.f) this.c, mVar, aVar, (com.quizlet.quizletandroid.ui.navigationmanagers.h) this.g, (com.quizlet.features.infra.google.e) this.h, (com.quizlet.features.settings.viewmodels.o) this.i, function2, function13, (InterfaceC0806l) obj, iH4);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.b | 1);
                Function2 function22 = (Function2) this.i;
                Function2 function23 = (Function2) this.j;
                B5.b((Function0) this.c, (Function0) this.d, (androidx.compose.ui.q) this.e, (com.quizlet.ui.compose.N) this.h, (Function1) this.f, (Function1) this.g, function22, function23, (InterfaceC0806l) obj, iH5);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ E(com.quizlet.features.settings.data.models.f fVar, com.quizlet.data.interactor.folderwithcreator.m mVar, com.quizlet.features.infra.logout.composables.a aVar, com.quizlet.quizletandroid.ui.navigationmanagers.h hVar, com.quizlet.features.infra.google.e eVar, com.quizlet.features.settings.viewmodels.o oVar, Function2 function2, Function1 function1, int i) {
        this.a = 3;
        this.c = fVar;
        this.d = mVar;
        this.e = aVar;
        this.g = hVar;
        this.h = eVar;
        this.i = oVar;
        this.j = function2;
        this.f = function1;
        this.b = i;
    }

    public /* synthetic */ E(Object obj, androidx.compose.ui.q qVar, Object obj2, InterfaceC4938g interfaceC4938g, InterfaceC4938g interfaceC4938g2, InterfaceC4938g interfaceC4938g3, Object obj3, Object obj4, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.d = qVar;
        this.e = obj2;
        this.f = interfaceC4938g;
        this.g = interfaceC4938g2;
        this.h = interfaceC4938g3;
        this.i = obj3;
        this.j = obj4;
        this.b = i;
    }

    public /* synthetic */ E(Function0 function0, Function0 function02, androidx.compose.ui.q qVar, com.quizlet.ui.compose.N n, Function1 function1, Function1 function12, Function2 function2, Function2 function22, int i) {
        this.a = 4;
        this.c = function0;
        this.d = function02;
        this.e = qVar;
        this.h = n;
        this.f = function1;
        this.g = function12;
        this.i = function2;
        this.j = function22;
        this.b = i;
    }
}
