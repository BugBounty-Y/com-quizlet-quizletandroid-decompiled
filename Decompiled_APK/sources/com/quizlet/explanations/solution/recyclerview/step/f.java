package com.quizlet.explanations.solution.recyclerview.step;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import androidx.navigation.U;
import com.google.android.gms.internal.mlkit_vision_barcode.z7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3634h5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P;
import com.quizlet.assembly.compose.modals.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class f implements Function2 {
    public final /* synthetic */ int a = 3;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ f(int i, Function1 function1, q qVar, boolean z, int i2) {
        this.c = i;
        this.d = function1;
        this.e = qVar;
        this.b = z;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.c | 1);
                boolean z = this.b;
                U u = (U) this.e;
                i.e((c) this.d, z, u, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.c | 1);
                x xVar = (x) this.d;
                Function1 function1 = (Function1) this.e;
                z7.c(this.b, xVar, function1, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                P.f(C0776c.H(this.c | 1), (InterfaceC0806l) obj, (Function0) this.d, (Function0) this.e, this.b);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(1);
                q qVar = (q) this.e;
                boolean z2 = this.b;
                AbstractC3634h5.g(this.c, (Function1) this.d, qVar, z2, (InterfaceC0806l) obj, iH3);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ f(c cVar, boolean z, U u, int i) {
        this.d = cVar;
        this.b = z;
        this.e = u;
        this.c = i;
    }

    public /* synthetic */ f(Function0 function0, Function0 function02, boolean z, int i) {
        this.d = function0;
        this.e = function02;
        this.b = z;
        this.c = i;
    }

    public /* synthetic */ f(boolean z, x xVar, Function1 function1, int i) {
        this.b = z;
        this.d = xVar;
        this.e = function1;
        this.c = i;
    }
}
