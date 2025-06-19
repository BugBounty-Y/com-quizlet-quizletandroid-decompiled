package com.quizlet.assembly.compose.modals;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0853m;
import com.google.android.gms.internal.mlkit_vision_camera.V1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3543u4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.I6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.T5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class h implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;

    public /* synthetic */ h(int i, int i2, androidx.compose.ui.graphics.painter.b bVar, String str, androidx.compose.ui.n nVar, boolean z, Function0 function0, Function0 function02, int i3) {
        this.b = i;
        this.c = i2;
        this.f = bVar;
        this.g = str;
        this.h = nVar;
        this.d = z;
        this.e = function0;
        this.i = function02;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.b | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.i;
                T5.a((androidx.compose.ui.q) this.f, (x) this.g, this.d, (C) this.h, (Function0) this.e, dVar, (InterfaceC0806l) obj, iH, this.c);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                Function0 function0 = (Function0) this.e;
                Function0 function02 = (Function0) this.i;
                V1.E(this.b, this.c, (androidx.compose.ui.graphics.painter.b) this.f, (String) this.g, (androidx.compose.ui.n) this.h, this.d, function0, function02, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.b | 1);
                Function0 function03 = (Function0) this.i;
                AbstractC3543u4.a((com.quizlet.learn.ui.g) this.g, this.d, (androidx.compose.ui.q) this.f, (Function0) this.e, (Function0) this.h, function03, (InterfaceC0806l) obj, iH3, this.c);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(this.b | 1);
                C0853m c0853m = (C0853m) this.i;
                Y5.f((String) this.f, (androidx.compose.ui.graphics.painter.b) this.g, (Function0) this.e, (androidx.compose.ui.n) this.h, this.d, c0853m, (InterfaceC0806l) obj, iH4, this.c);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.b | 1);
                String str = (String) this.i;
                androidx.compose.ui.q qVar = (androidx.compose.ui.q) this.f;
                I6.d((String) this.g, this.d, (Function1) this.h, (String) this.e, str, qVar, (InterfaceC0806l) obj, iH5, this.c);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ h(androidx.compose.ui.q qVar, x xVar, boolean z, C c, Function0 function0, androidx.compose.runtime.internal.d dVar, int i, int i2) {
        this.f = qVar;
        this.g = xVar;
        this.d = z;
        this.h = c;
        this.e = function0;
        this.i = dVar;
        this.b = i;
        this.c = i2;
    }

    public /* synthetic */ h(com.quizlet.learn.ui.g gVar, boolean z, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, Function0 function03, int i, int i2) {
        this.g = gVar;
        this.d = z;
        this.f = qVar;
        this.e = function0;
        this.h = function02;
        this.i = function03;
        this.b = i;
        this.c = i2;
    }

    public /* synthetic */ h(String str, androidx.compose.ui.graphics.painter.b bVar, Function0 function0, androidx.compose.ui.n nVar, boolean z, C0853m c0853m, int i, int i2) {
        this.f = str;
        this.g = bVar;
        this.e = function0;
        this.h = nVar;
        this.d = z;
        this.i = c0853m;
        this.b = i;
        this.c = i2;
    }

    public /* synthetic */ h(String str, boolean z, Function1 function1, String str2, String str3, androidx.compose.ui.q qVar, int i, int i2) {
        this.g = str;
        this.d = z;
        this.h = function1;
        this.e = str2;
        this.i = str3;
        this.f = qVar;
        this.b = i;
        this.c = i2;
    }
}
