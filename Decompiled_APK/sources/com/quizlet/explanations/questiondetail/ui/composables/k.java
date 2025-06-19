package com.quizlet.explanations.questiondetail.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3269u0;
import com.google.android.gms.internal.mlkit_vision_barcode.F5;
import com.google.android.gms.internal.mlkit_vision_barcode.N4;
import com.google.android.gms.internal.mlkit_vision_barcode.V4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3634h5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3698p5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.l7;
import com.quizlet.data.model.EnumC4159q0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class k implements Function2 {
    public final /* synthetic */ int a = 4;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ Function0 f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;

    public /* synthetic */ k(androidx.compose.ui.n nVar, boolean z, String str, com.quizlet.features.infra.folder.menu.viewmodel.n nVar2, com.quizlet.features.infra.folder.save.viewmodel.c cVar, Function0 function0, Function1 function1, int i) {
        this.d = nVar;
        this.e = z;
        this.b = str;
        this.g = nVar2;
        this.h = cVar;
        this.f = function0;
        this.c = function1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                String str = (String) this.b;
                Function0 function0 = this.f;
                Function1 function1 = (Function1) this.c;
                l7.a((androidx.compose.ui.n) this.d, this.e, str, (com.quizlet.features.infra.folder.menu.viewmodel.n) this.g, (com.quizlet.features.infra.folder.save.viewmodel.c) this.h, function0, function1, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                Function0 function02 = this.f;
                Function0 function03 = (Function0) this.h;
                V4.b((String) this.b, (Function1) this.c, (androidx.compose.ui.n) this.d, this.e, (EnumC4159q0) this.g, function02, function03, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(1);
                Function0 function04 = this.f;
                Function0 function05 = (Function0) this.h;
                F5.a(this.e, (Function1) this.c, (androidx.compose.ui.q) this.d, (String) this.b, (String) this.g, function04, function05, (InterfaceC0806l) obj, iH3);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(1);
                Function1 function12 = (Function1) this.h;
                boolean z = this.e;
                AbstractC3634h5.e((AbstractC3698p5) this.d, this.f, (Function1) this.c, (Function1) this.b, (Function1) this.g, function12, z, (InterfaceC0806l) obj, iH4);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(1);
                Function0 function06 = (Function0) this.g;
                Function1 function13 = (Function1) this.h;
                AbstractC3269u0.e((androidx.compose.ui.focus.h) this.d, this.e, (String) this.b, (Function1) this.c, this.f, function06, function13, (InterfaceC0806l) obj, iH5);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(1);
                androidx.compose.ui.q qVar = (androidx.compose.ui.q) this.c;
                boolean z2 = this.e;
                N4.a((String) this.b, (String) this.d, (com.quizlet.security.challenge.viewmodel.a) this.g, this.f, (Function0) this.h, qVar, z2, (InterfaceC0806l) obj, iH6);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ k(androidx.compose.ui.focus.h hVar, boolean z, String str, Function1 function1, Function0 function0, Function0 function02, Function1 function12, int i) {
        this.d = hVar;
        this.e = z;
        this.b = str;
        this.c = function1;
        this.f = function0;
        this.g = function02;
        this.h = function12;
    }

    public /* synthetic */ k(AbstractC3698p5 abstractC3698p5, Function0 function0, Function1 function1, Function1 function12, Function1 function13, Function1 function14, boolean z, int i) {
        this.d = abstractC3698p5;
        this.f = function0;
        this.c = function1;
        this.b = function12;
        this.g = function13;
        this.h = function14;
        this.e = z;
    }

    public /* synthetic */ k(String str, String str2, com.quizlet.security.challenge.viewmodel.a aVar, Function0 function0, Function0 function02, androidx.compose.ui.q qVar, boolean z, int i) {
        this.b = str;
        this.d = str2;
        this.g = aVar;
        this.f = function0;
        this.h = function02;
        this.c = qVar;
        this.e = z;
    }

    public /* synthetic */ k(String str, Function1 function1, androidx.compose.ui.n nVar, boolean z, EnumC4159q0 enumC4159q0, Function0 function0, Function0 function02, int i) {
        this.b = str;
        this.c = function1;
        this.d = nVar;
        this.e = z;
        this.g = enumC4159q0;
        this.f = function0;
        this.h = function02;
    }

    public /* synthetic */ k(boolean z, Function1 function1, androidx.compose.ui.q qVar, String str, String str2, Function0 function0, Function0 function02, int i) {
        this.e = z;
        this.c = function1;
        this.d = qVar;
        this.b = str;
        this.g = str2;
        this.f = function0;
        this.h = function02;
    }
}
