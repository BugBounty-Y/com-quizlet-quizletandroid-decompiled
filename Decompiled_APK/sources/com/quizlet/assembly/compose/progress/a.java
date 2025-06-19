package com.quizlet.assembly.compose.progress;

import androidx.compose.material3.L3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import androidx.glance.p;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3134e6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3225o7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3253s0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3259s6;
import com.google.android.gms.internal.mlkit_vision_barcode.G4;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3379p2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.K2;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import com.google.android.gms.internal.mlkit_vision_camera.X1;
import com.google.android.gms.internal.mlkit_vision_camera.n3;
import com.google.android.gms.internal.mlkit_vision_camera.o3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3497n;
import com.google.android.gms.internal.mlkit_vision_common.B;
import com.google.android.gms.internal.mlkit_vision_common.Y3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3579a6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3603d6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3659k6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.h7;
import com.google.common.util.concurrent.b;
import com.quizlet.assembly.widgets.progress.d;
import com.quizlet.baseui.base.BaseComposeBottomSheetFragment;
import com.quizlet.data.model.C2;
import com.quizlet.data.model.EssayItem;
import com.quizlet.features.folders.data.Q0;
import com.quizlet.features.infra.folder.tag.screenstates.k;
import com.quizlet.features.onboarding.ell.v;
import com.quizlet.features.practicetest.detail.data.I;
import com.quizlet.features.questionnaire.navigation.Progress;
import com.quizlet.features.questionnaire.screens.g;
import com.quizlet.features.questionnaire.steps.c;
import com.quizlet.features.questiontypes.basequestion.i;
import com.quizlet.features.questiontypes.selfassessment.h;
import com.quizlet.features.universaluploadflow.flashcards.data.s;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.collections.immutable.e;
import kotlinx.coroutines.flow.Y;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ a(int i, int i2, q qVar, Function1 function1) {
        this.a = 4;
        this.d = qVar;
        this.c = function1;
        this.b = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        Integer num = (Integer) obj2;
        switch (this.a) {
            case 0:
                num.getClass();
                AbstractC3603d6.b((d) this.c, (q) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 1:
                num.getClass();
                AbstractC3659k6.a((L3) this.c, (n) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 2:
                num.getClass();
                AbstractC3659k6.b((q) this.d, (androidx.compose.runtime.internal.d) this.c, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 3:
                num.getClass();
                int iH = C0776c.H(this.b | 1);
                ((BaseComposeBottomSheetFragment) this.c).R((androidx.compose.runtime.internal.d) this.d, interfaceC0806l, iH);
                break;
            case 4:
                num.getClass();
                b.b(this.b, C0776c.H(1), interfaceC0806l, (q) this.d, (Function1) this.c);
                break;
            case 5:
                num.intValue();
                AbstractC3253s0.a((DiagramData) this.c, (Function0) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 6:
                num.intValue();
                G4.a(C0776c.H(this.b | 1), interfaceC0806l, (Q0) this.c, (Function1) this.d);
                break;
            case 7:
                num.getClass();
                int iH2 = C0776c.H(this.b | 1);
                AbstractC3134e6.c((Function0) this.c, (androidx.compose.runtime.internal.d) this.d, interfaceC0806l, iH2);
                break;
            case 8:
                num.getClass();
                AbstractC3259s6.d((e) this.c, (Function1) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 9:
                num.intValue();
                AbstractC3259s6.a((k) this.c, (Function1) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 10:
                num.getClass();
                AbstractC3225o7.a((EssayItem) this.c, (Function0) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 11:
                num.getClass();
                AbstractC3409x1.e((Function1) this.c, (n) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 12:
                num.intValue();
                AbstractC3409x1.c((v) this.c, (Function1) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 13:
                num.getClass();
                int iH3 = C0776c.H(1);
                W1.J((I) this.c, (Function1) this.d, interfaceC0806l, iH3, this.b);
                break;
            case 14:
                num.getClass();
                int iH4 = C0776c.H(1);
                X1.a((com.quizlet.features.practicetest.common.data.a) this.c, this.b, (q) this.d, interfaceC0806l, iH4);
                break;
            case 15:
                num.getClass();
                AbstractC3379p2.b((com.quizlet.features.practicetest.takingtest.e) this.c, (Function0) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 16:
                num.getClass();
                int iH5 = C0776c.H(1);
                com.quizlet.features.questionnaire.progress.d.b((Progress) this.c, (q) this.d, interfaceC0806l, iH5, this.b);
                break;
            case 17:
                num.getClass();
                com.quizlet.features.questionnaire.screens.b.a((com.quizlet.features.questionnaire.steps.a) this.c, (q) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 18:
                num.getClass();
                g.a((c) this.c, (q) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 19:
                num.getClass();
                K2.a((Y) this.c, (i) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 20:
                num.intValue();
                n3.b((i) this.c, (h) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 21:
                num.getClass();
                o3.a((StudiableImage) this.c, (Function1) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case EventType.WINDOW_STATE /* 22 */:
                num.getClass();
                int iH6 = C0776c.H(1);
                AbstractC3497n.b((kotlinx.collections.immutable.b) this.c, (q) this.d, this.b, interfaceC0806l, iH6);
                break;
            case EventType.AUDIO /* 23 */:
                num.getClass();
                int iH7 = C0776c.H(1);
                B.c(this.b, (com.quizlet.features.setpage.studypreview.g) this.c, (n) this.d, interfaceC0806l, iH7);
                break;
            case EventType.VIDEO /* 24 */:
                num.getClass();
                int iH8 = C0776c.H(1);
                Y3.f((s) this.c, (Function1) this.d, interfaceC0806l, iH8, this.b);
                break;
            case EventType.SUBS /* 25 */:
                num.getClass();
                AbstractC3579a6.b((kotlinx.collections.immutable.b) this.c, (Function1) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case EventType.CDN /* 26 */:
                num.getClass();
                D6.k((m) this.c, (Function1) this.d, interfaceC0806l, C0776c.H(1), this.b);
                break;
            case 27:
                num.intValue();
                com.quizlet.quizletandroid.ui.studymodes.testmode.compose.m.b((G) this.c, (t) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 28:
                num.getClass();
                h7.c((Integer) this.c, (q) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            default:
                num.getClass();
                com.quizlet.features.universaluploadflow.navigation.c.b((C2) this.c, (p) this.d, interfaceC0806l, C0776c.H(1), this.b);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ a(int i, com.quizlet.features.setpage.studypreview.g gVar, n nVar, int i2) {
        this.a = 23;
        this.b = i;
        this.c = gVar;
        this.d = nVar;
    }

    public /* synthetic */ a(q qVar, androidx.compose.runtime.internal.d dVar, int i) {
        this.a = 2;
        this.d = qVar;
        this.c = dVar;
        this.b = i;
    }

    public /* synthetic */ a(com.quizlet.features.practicetest.common.data.a aVar, int i, q qVar, int i2) {
        this.a = 14;
        this.c = aVar;
        this.b = i;
        this.d = qVar;
    }

    public /* synthetic */ a(Object obj, Object obj2, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.d = obj2;
        this.b = i;
    }

    public /* synthetic */ a(Object obj, Object obj2, int i, int i2, int i3) {
        this.a = i3;
        this.c = obj;
        this.d = obj2;
        this.b = i2;
    }

    public /* synthetic */ a(Function0 function0, androidx.compose.runtime.internal.d dVar, int i) {
        this.a = 7;
        this.c = function0;
        this.d = dVar;
        this.b = i;
    }

    public /* synthetic */ a(kotlinx.collections.immutable.b bVar, q qVar, int i, int i2) {
        this.a = 22;
        this.c = bVar;
        this.d = qVar;
        this.b = i;
    }
}
