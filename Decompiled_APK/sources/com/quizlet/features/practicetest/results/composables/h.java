package com.quizlet.features.practicetest.results.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import androidx.transition.C1405h;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3218o0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class h implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ String b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ Function0 d;
    public final /* synthetic */ int e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;

    public /* synthetic */ h(n nVar, String str, boolean z, androidx.compose.ui.focus.h hVar, Function1 function1, Function0 function0, Function1 function12, int i, int i2) {
        this.f = nVar;
        this.b = str;
        this.c = z;
        this.g = hVar;
        this.h = function1;
        this.d = function0;
        this.i = function12;
        this.e = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                int iH = C0776c.H(1);
                C1405h.b(this.b, this.e, (com.quizlet.features.practicetest.results.data.d) this.h, this.c, (q) this.i, (String) this.f, (String) this.g, this.d, interfaceC0806l, iH);
                break;
            default:
                int iH2 = C0776c.H(1);
                AbstractC3218o0.b((n) this.f, this.b, this.c, (androidx.compose.ui.focus.h) this.g, (Function1) this.h, this.d, (Function1) this.i, interfaceC0806l, iH2, this.e);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ h(String str, int i, com.quizlet.features.practicetest.results.data.d dVar, boolean z, q qVar, String str2, String str3, Function0 function0, int i2) {
        this.b = str;
        this.e = i;
        this.h = dVar;
        this.c = z;
        this.i = qVar;
        this.f = str2;
        this.g = str3;
        this.d = function0;
    }
}
