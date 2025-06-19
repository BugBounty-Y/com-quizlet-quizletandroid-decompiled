package androidx.navigation.compose;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_camera.Q1;
import com.quizlet.diagrams.ui.DiagramJSBridge;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Home;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final /* synthetic */ class D implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ androidx.compose.ui.n b;
    public final /* synthetic */ Function1 c;
    public final /* synthetic */ Function1 d;
    public final /* synthetic */ int e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ InterfaceC4938g j;
    public final /* synthetic */ InterfaceC4938g k;
    public final /* synthetic */ InterfaceC4938g l;

    public /* synthetic */ D(androidx.navigation.H h, GlobalNavSuiteItem$Home globalNavSuiteItem$Home, androidx.compose.ui.n nVar, androidx.compose.ui.i iVar, kotlin.collections.L l, Function1 function1, Function1 function12, Function1 function13, Function1 function14, Function1 function15, int i) {
        this.f = h;
        this.g = globalNavSuiteItem$Home;
        this.b = nVar;
        this.h = iVar;
        this.i = l;
        this.c = function1;
        this.d = function12;
        this.j = function13;
        this.k = function14;
        this.l = function15;
        this.e = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.e | 1);
                Function1 function1 = (Function1) this.k;
                Function1 function12 = (Function1) this.l;
                Q1.c((androidx.navigation.H) this.f, (GlobalNavSuiteItem$Home) this.g, this.b, (androidx.compose.ui.i) this.h, (kotlin.collections.L) this.i, this.c, this.d, (Function1) this.j, function1, function12, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.e | 1);
                DiagramJSBridge diagramJSBridge = (DiagramJSBridge) this.g;
                io.ktor.client.plugins.api.d dVar = (io.ktor.client.plugins.api.d) this.h;
                kotlin.jvm.functions.c cVar = (kotlin.jvm.functions.c) this.l;
                Function1 function13 = this.d;
                com.google.android.gms.internal.mlkit_vision_common.E.a((com.quizlet.features.setpage.termlist.data.n) this.f, diagramJSBridge, dVar, this.b, (Function0) this.i, this.c, (Function2) this.j, (kotlin.jvm.functions.d) this.k, cVar, function13, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ D(com.quizlet.features.setpage.termlist.data.n nVar, DiagramJSBridge diagramJSBridge, io.ktor.client.plugins.api.d dVar, androidx.compose.ui.n nVar2, Function0 function0, Function1 function1, Function2 function2, kotlin.jvm.functions.d dVar2, kotlin.jvm.functions.c cVar, Function1 function12, int i) {
        this.f = nVar;
        this.g = diagramJSBridge;
        this.h = dVar;
        this.b = nVar2;
        this.i = function0;
        this.c = function1;
        this.j = function2;
        this.k = dVar2;
        this.l = cVar;
        this.d = function12;
        this.e = i;
    }
}
