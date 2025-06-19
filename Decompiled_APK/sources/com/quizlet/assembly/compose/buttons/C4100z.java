package com.quizlet.assembly.compose.buttons;

import androidx.compose.foundation.C0555x;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3586b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.V4;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.assembly.compose.buttons.z, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4100z implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ Object b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ Function0 d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ int g;
    public final /* synthetic */ int h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ Object j;
    public final /* synthetic */ Object k;
    public final /* synthetic */ Object l;

    public /* synthetic */ C4100z(androidx.compose.ui.graphics.painter.b bVar, String str, C4078c c4078c, androidx.compose.ui.q qVar, Function0 function0, boolean z, C c, B b, C0555x c0555x, int i, int i2) {
        this.f = bVar;
        this.b = str;
        this.i = c4078c;
        this.c = qVar;
        this.d = function0;
        this.e = z;
        this.j = c;
        this.k = b;
        this.l = c0555x;
        this.g = i;
        this.h = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.g | 1);
                C4078c c4078c = (C4078c) this.i;
                C c = (C) this.j;
                C0555x c0555x = (C0555x) this.l;
                V4.a((androidx.compose.ui.graphics.painter.b) this.f, (String) this.b, c4078c, this.c, this.d, this.e, c, (B) this.k, c0555x, (InterfaceC0806l) obj, iH, this.h);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.g | 1);
                androidx.compose.ui.graphics.painter.b bVar = (androidx.compose.ui.graphics.painter.b) this.f;
                AbstractC3586b5.a((String) this.b, this.c, this.d, this.e, (O) this.i, (InterfaceC4099y) this.j, (C4076a) this.k, (InterfaceC4092q) this.l, bVar, (InterfaceC0806l) obj, iH2, this.h);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.g | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.b;
                androidx.compose.runtime.internal.d dVar2 = (androidx.compose.runtime.internal.d) this.i;
                Function0 function0 = this.d;
                U5.a((com.quizlet.assembly.compose.modals.x) this.f, dVar, this.c, dVar2, (com.quizlet.assembly.compose.modals.C) this.j, (com.quizlet.assembly.compose.modals.C) this.k, (androidx.compose.ui.window.r) this.l, this.e, function0, (InterfaceC0806l) obj, iH3, this.h);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ C4100z(com.quizlet.assembly.compose.modals.x xVar, androidx.compose.runtime.internal.d dVar, androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar2, com.quizlet.assembly.compose.modals.C c, com.quizlet.assembly.compose.modals.C c2, androidx.compose.ui.window.r rVar, boolean z, Function0 function0, int i, int i2) {
        this.f = xVar;
        this.b = dVar;
        this.c = qVar;
        this.i = dVar2;
        this.j = c;
        this.k = c2;
        this.l = rVar;
        this.e = z;
        this.d = function0;
        this.g = i;
        this.h = i2;
    }

    public /* synthetic */ C4100z(String str, androidx.compose.ui.q qVar, Function0 function0, boolean z, O o, InterfaceC4099y interfaceC4099y, C4076a c4076a, InterfaceC4092q interfaceC4092q, androidx.compose.ui.graphics.painter.b bVar, int i, int i2) {
        this.b = str;
        this.c = qVar;
        this.d = function0;
        this.e = z;
        this.i = o;
        this.j = interfaceC4099y;
        this.k = c4076a;
        this.l = interfaceC4092q;
        this.f = bVar;
        this.g = i;
        this.h = i2;
    }
}
