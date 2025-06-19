package com.quizlet.login.common.ui;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3658k5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.F6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.G;
import com.google.android.gms.internal.mlkit_vision_document_scanner.I6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.V6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W6;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.login.common.interactors.data.C4590a;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ a(com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f fVar, String str, q qVar, Function1 function1, int i) {
        this.a = 7;
        this.d = fVar;
        this.e = str;
        this.b = qVar;
        this.c = function1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                C4590a c4590a = (C4590a) this.d;
                q qVar = (q) this.b;
                com.quizlet.time.b bVar = (com.quizlet.time.b) this.e;
                C.a((Function1) this.c, c4590a, qVar, bVar, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                Function0 function0 = (Function0) this.e;
                q qVar2 = (q) this.b;
                G.b((com.quizlet.login.authentication.k) this.c, (Function0) this.d, function0, qVar2, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(1);
                n nVar = (n) this.b;
                Function0 function02 = (Function0) this.e;
                AbstractC3658k5.d((String) this.c, (String) this.d, nVar, function02, (InterfaceC0806l) obj, iH3);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(7);
                q qVar3 = (q) this.b;
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a aVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a) this.e;
                D6.g((Function1) this.c, (Function0) this.d, qVar3, aVar, (InterfaceC0806l) obj, iH4);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(9);
                Function0 function03 = (Function0) this.e;
                q qVar4 = (q) this.b;
                F6.c((x) this.c, (Function0) this.d, function03, qVar4, (InterfaceC0806l) obj, iH5);
                break;
            case 5:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(1);
                q qVar5 = (q) this.b;
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.a aVar2 = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.a) this.e;
                I6.b((Function0) this.c, (Function0) this.d, qVar5, aVar2, (InterfaceC0806l) obj, iH6);
                break;
            case 6:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(1);
                String str = (String) this.d;
                androidx.compose.ui.graphics.painter.b bVar2 = (androidx.compose.ui.graphics.painter.b) this.e;
                V6.a((String) this.c, (q) this.b, str, bVar2, (InterfaceC0806l) obj, iH7);
                break;
            case 7:
                ((Integer) obj2).getClass();
                int iH8 = C0776c.H(1);
                q qVar6 = (q) this.b;
                Function1 function1 = (Function1) this.c;
                W6.a((com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f) this.d, (String) this.e, qVar6, function1, (InterfaceC0806l) obj, iH8);
                break;
            case 8:
                ((Integer) obj2).getClass();
                int iH9 = C0776c.H(1);
                Function0 function04 = (Function0) this.b;
                n nVar2 = (n) this.e;
                com.google.mlkit.common.model.a.b((com.quizlet.quizletandroid.ui.subject.viewmodel.h) this.c, (Function0) this.d, function04, nVar2, (InterfaceC0806l) obj, iH9);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH10 = C0776c.H(3073);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.e;
                P5.a(this.c, (Function0) this.d, (com.quizlet.ui.compose.util.a) this.b, dVar, (InterfaceC0806l) obj, iH10);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ a(Object obj, Object obj2, Object obj3, Object obj4, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.d = obj2;
        this.b = obj3;
        this.e = obj4;
    }

    public /* synthetic */ a(Object obj, Function0 function0, Function0 function02, q qVar, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.d = function0;
        this.e = function02;
        this.b = qVar;
    }

    public /* synthetic */ a(String str, q qVar, String str2, androidx.compose.ui.graphics.painter.b bVar, int i) {
        this.a = 6;
        this.c = str;
        this.b = qVar;
        this.d = str2;
        this.e = bVar;
    }
}
