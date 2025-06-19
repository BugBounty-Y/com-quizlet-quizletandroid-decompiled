package com.quizlet.features.questiontypes.selfassessment.ui;

import androidx.compose.foundation.layout.z0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import androidx.navigation.H;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3173j0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3277v0;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_camera.l3;
import com.google.android.gms.internal.mlkit_vision_camera.n3;
import com.google.android.gms.internal.mlkit_vision_common.A;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3502n4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3531s4;
import com.google.android.gms.internal.mlkit_vision_common.G2;
import com.google.android.gms.internal.mlkit_vision_common.H2;
import com.google.android.gms.internal.mlkit_vision_common.I2;
import com.google.android.gms.internal.mlkit_vision_common.L2;
import com.google.android.gms.internal.mlkit_vision_common.N3;
import com.google.android.gms.internal.mlkit_vision_common.P2;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.internal.mlkit_vision_common.U2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3579a6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3736u4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3738u6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.F;
import com.google.android.gms.internal.mlkit_vision_document_scanner.T;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.c7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.e7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.g7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.h7;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.features.questiontypes.basequestion.i;
import com.quizlet.features.questiontypes.selfassessment.h;
import com.quizlet.features.settings.composables.j;
import com.quizlet.features.settings.composables.n;
import com.quizlet.features.settings.data.states.y;
import com.quizlet.features.settings.viewmodels.o;
import com.quizlet.features.settings.viewmodels.p;
import com.quizlet.features.universaluploadflow.data.C4458g;
import com.quizlet.features.universaluploadflow.data.G;
import com.quizlet.generated.enums.I1;
import com.quizlet.learn.data.C4536a;
import com.quizlet.login.magiclink.data.k;
import com.quizlet.quizletandroid.ui.studymodes.testmode.start.C4757a;
import com.quizlet.search.composables.D;
import com.quizlet.studiablemodels.DefaultQuestionSectionData;
import com.quizlet.studiablemodels.StudiableImage;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ a(int i, int i2, int i3, Object obj, Object obj2, Object obj3) {
        this.a = i3;
        this.b = i;
        this.d = obj;
        this.c = obj2;
        this.e = obj3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.b | 1);
                q qVar = (q) this.c;
                Function1 function1 = (Function1) this.e;
                l3.a((StudiableImage) this.d, qVar, function1, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                q qVar2 = (q) this.c;
                h hVar = (h) this.e;
                n3.c(this.b, (i) this.d, qVar2, hVar, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(1);
                com.quizlet.features.infra.models.a aVar = (com.quizlet.features.infra.models.a) this.c;
                Function0 function0 = (Function0) this.e;
                A.a(aVar, (StudiableImage) this.d, function0, (InterfaceC0806l) obj, iH3, this.b);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(this.b | 1);
                A.d((com.quizlet.features.infra.models.a) this.e, (q) this.c, (StudiableImage) this.d, (InterfaceC0806l) obj, iH4);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.b | 1);
                j jVar = (j) this.e;
                q qVar3 = (q) this.c;
                G2.a((y) this.d, jVar, qVar3, (InterfaceC0806l) obj, iH5);
                break;
            case 5:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(this.b | 1);
                q qVar4 = (q) this.c;
                C1608n c1608n = (C1608n) this.e;
                H2.c((y) this.d, qVar4, c1608n, (InterfaceC0806l) obj, iH6);
                break;
            case 6:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(this.b | 1);
                n nVar = (n) this.e;
                q qVar5 = (q) this.c;
                I2.b((y) this.d, nVar, qVar5, (InterfaceC0806l) obj, iH7);
                break;
            case 7:
                ((Integer) obj2).getClass();
                int iH8 = C0776c.H(this.b | 1);
                androidx.compose.runtime.internal.j jVar2 = (androidx.compose.runtime.internal.j) this.e;
                L2.b((z0) this.d, (y) this.c, jVar2, (InterfaceC0806l) obj, iH8);
                break;
            case 8:
                ((Integer) obj2).getClass();
                int iH9 = C0776c.H(1);
                p pVar = (p) this.c;
                o oVar = (o) this.e;
                int i = this.b;
                L2.f((H) this.d, pVar, oVar, i, (InterfaceC0806l) obj, iH9);
                break;
            case 9:
                ((Integer) obj2).getClass();
                int iH10 = C0776c.H(this.b | 1);
                q qVar6 = (q) this.c;
                Function0 function02 = (Function0) this.e;
                P2.b((y) this.d, qVar6, function02, (InterfaceC0806l) obj, iH10);
                break;
            case 10:
                ((Integer) obj2).getClass();
                int iH11 = C0776c.H(this.b | 1);
                com.quizlet.data.interactor.course.a aVar2 = (com.quizlet.data.interactor.course.a) this.c;
                Function0 function03 = (Function0) this.e;
                U2.b((com.quizlet.features.settings.data.states.d) this.d, aVar2, function03, (InterfaceC0806l) obj, iH11);
                break;
            case 11:
                ((Integer) obj2).getClass();
                int iH12 = C0776c.H(1);
                q qVar7 = (q) this.c;
                int i2 = this.b;
                N3.a((G) this.d, (Function1) this.e, qVar7, i2, (InterfaceC0806l) obj, iH12);
                break;
            case 12:
                ((Integer) obj2).getClass();
                int iH13 = C0776c.H(this.b | 1);
                S3.d((C4458g) this.d, (Function1) this.e, (q) this.c, (InterfaceC0806l) obj, iH13);
                break;
            case 13:
                ((Integer) obj2).intValue();
                int iH14 = C0776c.H(this.b | 1);
                AbstractC3502n4.f((String) this.d, (String) this.c, (Function0) this.e, (InterfaceC0806l) obj, iH14);
                break;
            case 14:
                ((Integer) obj2).getClass();
                int iH15 = C0776c.H(1);
                C4536a c4536a = (C4536a) this.d;
                Function0 function04 = (Function0) this.e;
                AbstractC3531s4.c(c4536a, (Function0) this.c, function04, (InterfaceC0806l) obj, iH15, this.b);
                break;
            case 15:
                ((Integer) obj2).getClass();
                F.a(C0776c.H(this.b | 1), (InterfaceC0806l) obj, (q) this.c, (Function0) this.d, (Function0) this.e);
                break;
            case 16:
                ((Integer) obj2).getClass();
                int iH16 = C0776c.H(this.b | 1);
                Function0 function05 = (Function0) this.c;
                Function1 function12 = (Function1) this.e;
                T.c((k) this.d, function05, function12, (InterfaceC0806l) obj, iH16);
                break;
            case 17:
                ((Integer) obj2).getClass();
                AbstractC3736u4.c(C0776c.H(this.b | 1), (InterfaceC0806l) obj, (androidx.compose.ui.n) this.e, (x) this.d, (Function0) this.c);
                break;
            case 18:
                ((Integer) obj2).getClass();
                int iH17 = C0776c.H(this.b | 1);
                Function1 function13 = (Function1) this.e;
                q qVar8 = (q) this.c;
                AbstractC3579a6.c((I1) this.d, function13, qVar8, (InterfaceC0806l) obj, iH17);
                break;
            case 19:
                ((Integer) obj2).getClass();
                int iH18 = C0776c.H(1);
                Function1 function14 = (Function1) this.e;
                AbstractC3738u6.a((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.p) this.d, (q) this.c, function14, (InterfaceC0806l) obj, iH18, this.b);
                break;
            case 20:
                ((Integer) obj2).getClass();
                int iH19 = C0776c.H(this.b | 1);
                W6.b((e7) this.d, (q) this.c, (Function1) this.e, (InterfaceC0806l) obj, iH19);
                break;
            case 21:
                ((Integer) obj2).getClass();
                int iH20 = C0776c.H(this.b | 1);
                q qVar9 = (q) this.c;
                Function1 function15 = (Function1) this.e;
                c7.a((DefaultQuestionSectionData) this.d, qVar9, function15, (InterfaceC0806l) obj, iH20);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                ((Integer) obj2).getClass();
                int iH21 = C0776c.H(this.b | 1);
                C4757a c4757a = (C4757a) this.c;
                androidx.compose.ui.n nVar2 = (androidx.compose.ui.n) this.e;
                g7.a((x) this.d, c4757a, nVar2, (InterfaceC0806l) obj, iH21);
                break;
            case EventType.AUDIO /* 23 */:
                ((Integer) obj2).getClass();
                int iH22 = C0776c.H(this.b | 1);
                com.quizlet.quizletandroid.ui.studymodes.testmode.start.j jVar3 = (com.quizlet.quizletandroid.ui.studymodes.testmode.start.j) this.e;
                q qVar10 = (q) this.c;
                h7.k((String) this.d, jVar3, qVar10, (InterfaceC0806l) obj, iH22);
                break;
            case EventType.VIDEO /* 24 */:
                ((Integer) obj2).getClass();
                int iH23 = C0776c.H(this.b | 1);
                C4757a c4757a2 = (C4757a) this.e;
                q qVar11 = (q) this.c;
                h7.a((Function0) this.d, c4757a2, qVar11, (InterfaceC0806l) obj, iH23);
                break;
            case EventType.SUBS /* 25 */:
                ((Integer) obj2).getClass();
                int iH24 = C0776c.H(this.b | 1);
                z0 z0Var = (z0) this.d;
                Function0 function06 = (Function0) this.e;
                AbstractC3173j0.b((q) this.c, z0Var, function06, (InterfaceC0806l) obj, iH24);
                break;
            case EventType.CDN /* 26 */:
                ((Integer) obj2).getClass();
                int iH25 = C0776c.H(1);
                D d = (D) this.c;
                androidx.compose.ui.n nVar3 = (androidx.compose.ui.n) this.e;
                AbstractC3277v0.d(this.b, (Function0) this.d, d, nVar3, (InterfaceC0806l) obj, iH25);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH26 = C0776c.H(this.b | 1);
                Function0 function07 = (Function0) this.c;
                com.quizlet.ui.compose.util.a aVar3 = (com.quizlet.ui.compose.util.a) this.e;
                P5.c(this.d, function07, aVar3, (InterfaceC0806l) obj, iH26);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ a(int i, int i2, int i3, Object obj, Object obj2, InterfaceC4938g interfaceC4938g) {
        this.a = i3;
        this.d = obj;
        this.c = obj2;
        this.e = interfaceC4938g;
        this.b = i2;
    }

    public /* synthetic */ a(int i, int i2, q qVar, Object obj, Object obj2) {
        this.a = i2;
        this.d = obj;
        this.e = obj2;
        this.c = qVar;
        this.b = i;
    }

    public /* synthetic */ a(int i, int i2, Object obj, Object obj2, Object obj3) {
        this.a = i2;
        this.d = obj;
        this.c = obj2;
        this.e = obj3;
        this.b = i;
    }

    public /* synthetic */ a(q qVar, z0 z0Var, Function0 function0, int i) {
        this.a = 25;
        this.c = qVar;
        this.d = z0Var;
        this.e = function0;
        this.b = i;
    }

    public /* synthetic */ a(H h, p pVar, o oVar, int i, int i2) {
        this.a = 8;
        this.d = h;
        this.c = pVar;
        this.e = oVar;
        this.b = i;
    }

    public /* synthetic */ a(com.quizlet.features.infra.models.a aVar, q qVar, StudiableImage studiableImage, int i) {
        this.a = 3;
        this.e = aVar;
        this.c = qVar;
        this.d = studiableImage;
        this.b = i;
    }

    public /* synthetic */ a(com.quizlet.features.infra.models.a aVar, StudiableImage studiableImage, Function0 function0, int i, int i2) {
        this.a = 2;
        this.c = aVar;
        this.d = studiableImage;
        this.e = function0;
        this.b = i2;
    }

    public /* synthetic */ a(G g, Function1 function1, q qVar, int i, int i2) {
        this.a = 11;
        this.d = g;
        this.e = function1;
        this.c = qVar;
        this.b = i;
    }
}
