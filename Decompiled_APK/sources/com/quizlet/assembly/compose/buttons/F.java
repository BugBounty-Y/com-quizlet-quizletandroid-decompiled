package com.quizlet.assembly.compose.buttons;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.P4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.X4;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class F implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ InterfaceC4938g d;
    public final /* synthetic */ int e;
    public final /* synthetic */ int f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;

    public /* synthetic */ F(com.quizlet.ui.models.content.listitem.a aVar, androidx.compose.ui.n nVar, boolean z, androidx.compose.runtime.internal.d dVar, boolean z2, Function0 function0, int i, int i2) {
        this.g = aVar;
        this.h = nVar;
        this.b = z;
        this.i = dVar;
        this.c = z2;
        this.d = function0;
        this.e = i;
        this.f = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.e | 1);
                Function0 function0 = (Function0) this.d;
                X4.a((String) this.g, this.b, (androidx.compose.ui.q) this.h, (G) this.i, this.c, function0, (InterfaceC0806l) obj, iH, this.f);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.e | 1);
                com.quizlet.ui.models.content.listitem.a aVar = (com.quizlet.ui.models.content.listitem.a) this.g;
                Function0 function02 = (Function0) this.d;
                C5.b(aVar, (androidx.compose.ui.n) this.h, this.b, (androidx.compose.runtime.internal.d) this.i, this.c, function02, (InterfaceC0806l) obj, iH2, this.f);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.f | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.d;
                P4.b((com.quizlet.ui.models.content.listitem.o) this.g, this.e, (Function1) this.h, this.b, this.c, (androidx.compose.foundation.lazy.A) this.i, dVar, (InterfaceC0806l) obj, iH3);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ F(com.quizlet.ui.models.content.listitem.o oVar, int i, Function1 function1, boolean z, boolean z2, androidx.compose.foundation.lazy.A a, androidx.compose.runtime.internal.d dVar, int i2) {
        this.g = oVar;
        this.e = i;
        this.h = function1;
        this.b = z;
        this.c = z2;
        this.i = a;
        this.d = dVar;
        this.f = i2;
    }

    public /* synthetic */ F(String str, boolean z, androidx.compose.ui.q qVar, G g, boolean z2, Function0 function0, int i, int i2) {
        this.g = str;
        this.b = z;
        this.h = qVar;
        this.i = g;
        this.c = z2;
        this.d = function0;
        this.e = i;
        this.f = i2;
    }
}
