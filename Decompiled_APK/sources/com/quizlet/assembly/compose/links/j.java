package com.quizlet.assembly.compose.links;

import androidx.compose.foundation.layout.A0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import androidx.compose.ui.text.C0995g;
import com.facebook.appevents.m;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.internal.mlkit_vision_camera.m3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3667l6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3769y5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3777z5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.M5;
import com.quizlet.assembly.compose.menu.r;
import com.quizlet.assembly.compose.menu.s;
import com.quizlet.features.practicetest.takingtest.data.C4412f;
import com.quizlet.features.practicetest.takingtest.data.InterfaceC4415i;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class j implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ q c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Function0 e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;

    public /* synthetic */ j(int i, com.quizlet.features.infra.models.flashcards.f fVar, com.quizlet.features.infra.models.flashcards.f fVar2, q qVar, Function0 function0, Function0 function02, Function1 function1, int i2) {
        this.a = 6;
        this.f = i;
        this.b = fVar;
        this.h = fVar2;
        this.c = qVar;
        this.e = function0;
        this.d = function02;
        this.i = function1;
        this.g = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.f | 1);
                Function0 function0 = this.e;
                AbstractC3769y5.a((String) this.b, this.c, (f) this.h, (A0) this.d, (a) this.i, function0, (InterfaceC0806l) obj, iH, this.g);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.f | 1);
                Function0 function02 = this.e;
                AbstractC3777z5.a((String) this.b, this.c, (i) this.h, (A0) this.d, (b) this.i, function02, (InterfaceC0806l) obj, iH2, this.g);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.f | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.b;
                Function0 function03 = this.e;
                M5.a(dVar, this.c, (s) this.h, (Function1) this.d, (r) this.i, function03, (InterfaceC0806l) obj, iH3, this.g);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(this.f | 1);
                com.quizlet.assembly.compose.toasts.f fVar = (com.quizlet.assembly.compose.toasts.f) this.i;
                AbstractC3667l6.c((C0995g) this.h, this.c, (String) this.b, this.e, (Function0) this.d, fVar, (InterfaceC0806l) obj, iH4, this.g);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.g | 1);
                String str = (String) this.b;
                String str2 = (String) this.d;
                String str3 = (String) this.i;
                q qVar = this.c;
                Function0 function04 = this.e;
                m.b(this.f, (kotlinx.collections.immutable.b) this.h, str, str2, str3, qVar, function04, (InterfaceC0806l) obj, iH5);
                break;
            case 5:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(this.g | 1);
                q qVar2 = this.c;
                int i = this.f;
                AbstractC3375o2.a((C4412f) this.b, (InterfaceC4415i) this.h, (Function1) this.d, (Function1) this.i, this.e, qVar2, i, (InterfaceC0806l) obj, iH6);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(this.g | 1);
                com.quizlet.features.infra.models.flashcards.f fVar2 = (com.quizlet.features.infra.models.flashcards.f) this.b;
                com.quizlet.features.infra.models.flashcards.f fVar3 = (com.quizlet.features.infra.models.flashcards.f) this.h;
                Function0 function05 = (Function0) this.d;
                Function1 function1 = (Function1) this.i;
                m3.b(this.f, fVar2, fVar3, this.c, this.e, function05, function1, (InterfaceC0806l) obj, iH7);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ j(int i, kotlinx.collections.immutable.b bVar, String str, String str2, String str3, q qVar, Function0 function0, int i2) {
        this.a = 4;
        this.f = i;
        this.h = bVar;
        this.b = str;
        this.d = str2;
        this.i = str3;
        this.c = qVar;
        this.e = function0;
        this.g = i2;
    }

    public /* synthetic */ j(C0995g c0995g, q qVar, String str, Function0 function0, Function0 function02, com.quizlet.assembly.compose.toasts.f fVar, int i, int i2) {
        this.a = 3;
        this.h = c0995g;
        this.c = qVar;
        this.b = str;
        this.e = function0;
        this.d = function02;
        this.i = fVar;
        this.f = i;
        this.g = i2;
    }

    public /* synthetic */ j(C4412f c4412f, InterfaceC4415i interfaceC4415i, Function1 function1, Function1 function12, Function0 function0, q qVar, int i, int i2) {
        this.a = 5;
        this.b = c4412f;
        this.h = interfaceC4415i;
        this.d = function1;
        this.i = function12;
        this.e = function0;
        this.c = qVar;
        this.f = i;
        this.g = i2;
    }

    public /* synthetic */ j(Object obj, q qVar, Object obj2, Object obj3, Object obj4, Function0 function0, int i, int i2, int i3) {
        this.a = i3;
        this.b = obj;
        this.c = qVar;
        this.h = obj2;
        this.d = obj3;
        this.i = obj4;
        this.e = function0;
        this.f = i;
        this.g = i2;
    }
}
