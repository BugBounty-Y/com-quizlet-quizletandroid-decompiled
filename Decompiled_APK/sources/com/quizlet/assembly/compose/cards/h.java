package com.quizlet.assembly.compose.cards;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import com.facebook.appevents.m;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3225o7;
import com.google.android.gms.internal.mlkit_vision_barcode.B0;
import com.google.android.gms.internal.mlkit_vision_barcode.C0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3344h;
import com.google.android.gms.internal.mlkit_vision_camera.F2;
import com.google.android.gms.internal.mlkit_vision_camera.n3;
import com.google.android.gms.internal.mlkit_vision_common.K2;
import com.google.android.gms.internal.mlkit_vision_common.T2;
import com.google.android.gms.internal.mlkit_vision_common.W2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3706q5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D;
import com.quizlet.data.model.EnumC4175w;
import com.quizlet.data.model.EssayItem;
import com.quizlet.features.folders.addtofolder.data.u;
import com.quizlet.features.settings.data.states.l;
import com.quizlet.search.data.term.TermSearchUiModel;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class h implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ int d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;

    public /* synthetic */ h(int i, int i2, int i3, q qVar, String str, String str2, Function0 function0, Function1 function1) {
        this.a = 10;
        this.e = str;
        this.f = function1;
        this.c = function0;
        this.g = qVar;
        this.h = str2;
        this.b = i;
        this.d = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.d | 1);
                com.quizlet.ui.compose.util.a aVar = (com.quizlet.ui.compose.util.a) this.h;
                Function0 function0 = this.c;
                AbstractC3706q5.a((com.quizlet.ui.models.content.carditem.h) this.e, (n) this.f, this.b, (Function2) this.g, aVar, function0, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.d | 1);
                String str = (String) this.e;
                String str2 = (String) this.f;
                String str3 = (String) this.g;
                q qVar = (q) this.h;
                Function0 function02 = this.c;
                m.c(this.b, str, str2, str3, qVar, function02, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.b | 1);
                Function0 function03 = this.c;
                B0.b((q) this.e, (u) this.f, (Function1) this.g, (Function1) this.h, function03, (InterfaceC0806l) obj, iH3, this.d);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(this.b | 1);
                Function0 function04 = (Function0) this.h;
                AbstractC3225o7.c((EssayItem) this.e, (EnumC4175w) this.f, (q) this.g, this.c, function04, (InterfaceC0806l) obj, iH4, this.d);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.b | 1);
                String str4 = (String) this.h;
                AbstractC3344h.a((String) this.e, (androidx.compose.ui.graphics.painter.b) this.f, this.c, (q) this.g, str4, (InterfaceC0806l) obj, iH5, this.d);
                break;
            case 5:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(this.b | 1);
                Function0 function05 = this.c;
                F2.c((com.quizlet.features.questiontypes.composables.a) this.e, (q) this.f, (com.quizlet.features.infra.models.a) this.g, (String) this.h, function05, (InterfaceC0806l) obj, iH6, this.d);
                break;
            case 6:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(this.d | 1);
                com.quizlet.features.questiontypes.selfassessment.data.a aVar2 = (com.quizlet.features.questiontypes.selfassessment.data.a) this.e;
                com.quizlet.features.questiontypes.selfassessment.h hVar = (com.quizlet.features.questiontypes.selfassessment.h) this.g;
                q qVar2 = (q) this.h;
                n3.a(this.b, aVar2, this.c, (com.quizlet.features.questiontypes.basequestion.i) this.f, hVar, qVar2, (InterfaceC0806l) obj, iH7);
                break;
            case 7:
                ((Integer) obj2).getClass();
                int iH8 = C0776c.H(this.b | 1);
                Function0 function06 = this.c;
                K2.a((String) this.e, (n) this.f, (String) this.h, (Function2) this.g, function06, (InterfaceC0806l) obj, iH8, this.d);
                break;
            case 8:
                ((Integer) obj2).getClass();
                int iH9 = C0776c.H(this.b | 1);
                Function1 function1 = (Function1) this.h;
                T2.b((String) this.e, (com.quizlet.features.settings.data.states.d) this.f, this.c, (Function0) this.g, function1, (InterfaceC0806l) obj, iH9, this.d);
                break;
            case 9:
                ((Integer) obj2).getClass();
                int iH10 = C0776c.H(this.b | 1);
                Function1 function12 = (Function1) this.h;
                W2.b((l) this.e, (String) this.f, this.c, (Function0) this.g, function12, (InterfaceC0806l) obj, iH10, this.d);
                break;
            case 10:
                ((Integer) obj2).getClass();
                int iH11 = C0776c.H(1);
                int i = this.b;
                int i2 = this.d;
                String str5 = (String) this.e;
                Function1 function13 = (Function1) this.f;
                D.a(i, iH11, i2, (InterfaceC0806l) obj, (q) this.g, str5, (String) this.h, this.c, function13);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH12 = C0776c.H(this.d | 1);
                com.quizlet.ui.compose.util.a aVar3 = (com.quizlet.ui.compose.util.a) this.h;
                Function0 function07 = this.c;
                C0.e((TermSearchUiModel) this.e, (n) this.f, this.b, (Function2) this.g, aVar3, function07, (InterfaceC0806l) obj, iH12);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ h(int i, com.quizlet.features.questiontypes.selfassessment.data.a aVar, Function0 function0, com.quizlet.features.questiontypes.basequestion.i iVar, com.quizlet.features.questiontypes.selfassessment.h hVar, q qVar, int i2) {
        this.a = 6;
        this.b = i;
        this.e = aVar;
        this.c = function0;
        this.f = iVar;
        this.g = hVar;
        this.h = qVar;
        this.d = i2;
    }

    public /* synthetic */ h(int i, String str, String str2, String str3, q qVar, Function0 function0, int i2) {
        this.a = 1;
        this.b = i;
        this.e = str;
        this.f = str2;
        this.g = str3;
        this.h = qVar;
        this.c = function0;
        this.d = i2;
    }

    public /* synthetic */ h(EssayItem essayItem, EnumC4175w enumC4175w, q qVar, Function0 function0, Function0 function02, int i, int i2) {
        this.a = 3;
        this.e = essayItem;
        this.f = enumC4175w;
        this.g = qVar;
        this.c = function0;
        this.h = function02;
        this.b = i;
        this.d = i2;
    }

    public /* synthetic */ h(Object obj, n nVar, int i, Function2 function2, com.quizlet.ui.compose.util.a aVar, Function0 function0, int i2, int i3) {
        this.a = i3;
        this.e = obj;
        this.f = nVar;
        this.b = i;
        this.g = function2;
        this.h = aVar;
        this.c = function0;
        this.d = i2;
    }

    public /* synthetic */ h(Object obj, Object obj2, Object obj3, Object obj4, Function0 function0, int i, int i2, int i3) {
        this.a = i3;
        this.e = obj;
        this.f = obj2;
        this.g = obj3;
        this.h = obj4;
        this.c = function0;
        this.b = i;
        this.d = i2;
    }

    public /* synthetic */ h(Object obj, Object obj2, Function0 function0, Object obj3, Object obj4, int i, int i2, int i3) {
        this.a = i3;
        this.e = obj;
        this.f = obj2;
        this.c = function0;
        this.g = obj3;
        this.h = obj4;
        this.b = i;
        this.d = i2;
    }

    public /* synthetic */ h(String str, n nVar, String str2, Function2 function2, Function0 function0, int i, int i2) {
        this.a = 7;
        this.e = str;
        this.f = nVar;
        this.h = str2;
        this.g = function2;
        this.c = function0;
        this.b = i;
        this.d = i2;
    }
}
