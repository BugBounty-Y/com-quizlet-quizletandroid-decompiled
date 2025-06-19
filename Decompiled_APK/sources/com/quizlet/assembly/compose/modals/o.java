package com.quizlet.assembly.compose.modals;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.O4;
import com.google.android.gms.internal.mlkit_vision_camera.T1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3537t4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.V5;
import com.quizlet.learn.data.AbstractC4540e;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4759a;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4760b;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.H;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.I;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class o implements Function2 {
    public final /* synthetic */ int a = 4;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ int g;
    public final /* synthetic */ int h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ Object j;

    public /* synthetic */ o(int i, int i2, androidx.compose.ui.q qVar, AbstractC4540e abstractC4540e, com.quizlet.learn.ui.g gVar, Function0 function0, Function0 function02, Function0 function03, boolean z) {
        this.g = i;
        this.c = abstractC4540e;
        this.d = z;
        this.i = gVar;
        this.b = qVar;
        this.e = function0;
        this.j = function02;
        this.f = function03;
        this.h = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.g | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.f;
                U5.b((x) this.c, (androidx.compose.ui.q) this.b, this.d, (z) this.i, (z) this.j, (Function0) this.e, dVar, (InterfaceC0806l) obj, iH, this.h);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.g | 1);
                androidx.compose.runtime.internal.d dVar2 = (androidx.compose.runtime.internal.d) this.f;
                V5.a((androidx.compose.ui.q) this.b, (x) this.c, this.d, (C) this.i, (Function0) this.e, (androidx.compose.ui.window.r) this.j, dVar2, (InterfaceC0806l) obj, iH2, this.h);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(1);
                Function1 function1 = (Function1) this.f;
                O4.c((androidx.compose.ui.focus.h) this.c, (androidx.compose.ui.n) this.b, this.d, this.g, (Function1) this.i, (Function0) this.e, (Function0) this.j, function1, (InterfaceC0806l) obj, iH3, this.h);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(1);
                boolean z = this.d;
                T1.a((String) this.c, (String) this.b, (Function0) this.e, (Function0) this.i, (androidx.compose.ui.n) this.j, this.g, (androidx.compose.ui.graphics.painter.b) this.f, z, (InterfaceC0806l) obj, iH4, this.h);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.h | 1);
                Function0 function0 = (Function0) this.j;
                Function0 function02 = (Function0) this.f;
                AbstractC3537t4.d(this.g, (AbstractC4540e) this.c, this.d, (com.quizlet.learn.ui.g) this.i, (androidx.compose.ui.q) this.b, (Function0) this.e, function0, function02, (InterfaceC0806l) obj, iH5);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(this.g | 1);
                Function1 function12 = (Function1) this.f;
                com.quizlet.quizletandroid.ui.studymodes.testmode.compose.m.c((C4759a) this.c, (I) this.i, (C4760b) this.j, (H) this.e, this.d, (androidx.compose.ui.q) this.b, function12, (InterfaceC0806l) obj, iH6, this.h);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ o(androidx.compose.ui.q qVar, x xVar, boolean z, C c, Function0 function0, androidx.compose.ui.window.r rVar, androidx.compose.runtime.internal.d dVar, int i, int i2) {
        this.b = qVar;
        this.c = xVar;
        this.d = z;
        this.i = c;
        this.e = function0;
        this.j = rVar;
        this.f = dVar;
        this.g = i;
        this.h = i2;
    }

    public /* synthetic */ o(androidx.compose.ui.focus.h hVar, androidx.compose.ui.n nVar, boolean z, int i, Function1 function1, Function0 function0, Function0 function02, Function1 function12, int i2, int i3) {
        this.c = hVar;
        this.b = nVar;
        this.d = z;
        this.g = i;
        this.i = function1;
        this.e = function0;
        this.j = function02;
        this.f = function12;
        this.h = i3;
    }

    public /* synthetic */ o(x xVar, androidx.compose.ui.q qVar, boolean z, z zVar, z zVar2, Function0 function0, androidx.compose.runtime.internal.d dVar, int i, int i2) {
        this.c = xVar;
        this.b = qVar;
        this.d = z;
        this.i = zVar;
        this.j = zVar2;
        this.e = function0;
        this.f = dVar;
        this.g = i;
        this.h = i2;
    }

    public /* synthetic */ o(C4759a c4759a, I i, C4760b c4760b, H h, boolean z, androidx.compose.ui.q qVar, Function1 function1, int i2, int i3) {
        this.c = c4759a;
        this.i = i;
        this.j = c4760b;
        this.e = h;
        this.d = z;
        this.b = qVar;
        this.f = function1;
        this.g = i2;
        this.h = i3;
    }

    public /* synthetic */ o(String str, String str2, Function0 function0, Function0 function02, androidx.compose.ui.n nVar, int i, androidx.compose.ui.graphics.painter.b bVar, boolean z, int i2, int i3) {
        this.c = str;
        this.b = str2;
        this.e = function0;
        this.i = function02;
        this.j = nVar;
        this.g = i;
        this.f = bVar;
        this.d = z;
        this.h = i3;
    }
}
