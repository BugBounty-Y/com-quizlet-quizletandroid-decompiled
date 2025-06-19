package coil3.compose;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.AbstractC0874w;
import androidx.compose.ui.layout.InterfaceC0889j;
import com.google.android.gms.internal.mlkit_vision_camera.p3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3667l6;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ String b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ int d;
    public final /* synthetic */ int e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ InterfaceC4938g g;
    public final /* synthetic */ InterfaceC4938g h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ Object j;
    public final /* synthetic */ Object k;

    public /* synthetic */ a(coil3.compose.internal.a aVar, String str, androidx.compose.ui.q qVar, Function1 function1, Function1 function12, androidx.compose.ui.d dVar, InterfaceC0889j interfaceC0889j, AbstractC0874w abstractC0874w, int i, int i2) {
        this.f = aVar;
        this.b = str;
        this.c = qVar;
        this.g = function1;
        this.h = function12;
        this.i = dVar;
        this.j = interfaceC0889j;
        this.k = abstractC0874w;
        this.d = i;
        this.e = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.d | 1);
                int iH2 = C0776c.H(this.e);
                coil3.compose.internal.a aVar = (coil3.compose.internal.a) this.f;
                InterfaceC0889j interfaceC0889j = (InterfaceC0889j) this.j;
                AbstractC0874w abstractC0874w = (AbstractC0874w) this.k;
                p3.a(aVar, this.b, this.c, (Function1) this.g, (Function1) this.h, (androidx.compose.ui.d) this.i, interfaceC0889j, abstractC0874w, (InterfaceC0806l) obj, iH, iH2);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.d | 1);
                com.quizlet.assembly.compose.toasts.f fVar = (com.quizlet.assembly.compose.toasts.f) this.k;
                AbstractC3667l6.b(this.b, this.c, (String) this.f, (Function0) this.g, (Function0) this.h, (Function0) this.i, (com.quizlet.assembly.compose.toasts.g) this.j, fVar, (InterfaceC0806l) obj, iH3, this.e);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ a(String str, androidx.compose.ui.q qVar, String str2, Function0 function0, Function0 function02, Function0 function03, com.quizlet.assembly.compose.toasts.g gVar, com.quizlet.assembly.compose.toasts.f fVar, int i, int i2) {
        this.b = str;
        this.c = qVar;
        this.f = str2;
        this.g = function0;
        this.h = function02;
        this.i = function03;
        this.j = gVar;
        this.k = fVar;
        this.d = i;
        this.e = i2;
    }
}
