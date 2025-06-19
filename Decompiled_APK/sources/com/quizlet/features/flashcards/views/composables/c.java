package com.quizlet.features.flashcards.views.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3253s0;
import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.google.android.gms.internal.mlkit_vision_barcode.P4;
import com.quizlet.generated.enums.y1;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ InterfaceC4938g h;
    public final /* synthetic */ InterfaceC4938g i;

    public /* synthetic */ c(D6 d6, boolean z, boolean z2, q qVar, Function0 function0, Function0 function02, Function1 function1, Function0 function03, int i) {
        this.e = d6;
        this.c = z;
        this.d = z2;
        this.f = qVar;
        this.g = function0;
        this.h = function02;
        this.b = function1;
        this.i = function03;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(3073);
                D6 d6 = (D6) this.e;
                Function1 function1 = this.b;
                Function0 function0 = (Function0) this.i;
                AbstractC3253s0.b(d6, this.c, this.d, (q) this.f, (Function0) this.g, (Function0) this.h, function1, function0, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(14155777);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.i;
                P4.a(this.b, (String) this.e, (y1) this.f, this.c, (androidx.compose.ui.n) this.g, this.d, (Function1) this.h, dVar, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ c(Function1 function1, String str, y1 y1Var, boolean z, androidx.compose.ui.n nVar, boolean z2, Function1 function12, androidx.compose.runtime.internal.d dVar, int i) {
        this.b = function1;
        this.e = str;
        this.f = y1Var;
        this.c = z;
        this.g = nVar;
        this.d = z2;
        this.h = function12;
        this.i = dVar;
    }
}
