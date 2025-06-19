package androidx.navigation.compose;

import androidx.compose.foundation.layout.z0;
import androidx.compose.material3.L3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.text.C0995g;
import androidx.navigation.C1291m;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3133e5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3169i5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3171i7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3189k7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3253s0;
import com.google.android.gms.internal.mlkit_vision_barcode.J6;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.M7;
import com.google.android.gms.internal.mlkit_vision_barcode.S5;
import com.google.android.gms.internal.mlkit_vision_barcode.X6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3394t2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.G1;
import com.google.android.gms.internal.mlkit_vision_camera.G2;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import com.google.android.gms.internal.mlkit_vision_camera.M1;
import com.google.android.gms.internal.mlkit_vision_camera.N1;
import com.google.android.gms.internal.mlkit_vision_camera.R2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3658k5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.B5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.N5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Z5;
import com.quizlet.data.model.C4114c;
import com.quizlet.data.model.C4166t;
import com.quizlet.data.model.m2;
import com.quizlet.data.model.v2;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final /* synthetic */ class u implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ u(int i, int i2, int i3, androidx.compose.ui.q qVar, Object obj, Object obj2) {
        this.a = i3;
        this.c = obj;
        this.d = qVar;
        this.e = obj2;
        this.b = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.b | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.e;
                M1.a((C1291m) this.c, (androidx.compose.runtime.saveable.f) this.d, dVar, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                com.quizlet.ui.models.content.carditem.b bVar = (com.quizlet.ui.models.content.carditem.b) this.c;
                Function1 function1 = (Function1) this.e;
                AbstractC3658k5.b(bVar, (androidx.compose.ui.q) this.d, function1, (InterfaceC0806l) obj, iH2, this.b);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(1);
                androidx.compose.ui.text.L l = (androidx.compose.ui.text.L) this.e;
                int i = this.b;
                B5.g((String) this.c, (androidx.compose.ui.n) this.d, l, i, (InterfaceC0806l) obj, iH3);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(this.b | 1);
                Function1 function12 = (Function1) this.d;
                Function0 function0 = (Function0) this.e;
                N5.b((com.quizlet.assembly.compose.menu.s) this.c, function12, function0, (InterfaceC0806l) obj, iH4);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.b | 1);
                androidx.compose.ui.n nVar = (androidx.compose.ui.n) this.d;
                com.quizlet.assembly.compose.modals.x xVar = (com.quizlet.assembly.compose.modals.x) this.e;
                Z5.c((String) this.c, nVar, xVar, (InterfaceC0806l) obj, iH5);
                break;
            case 5:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(this.b | 1);
                androidx.compose.ui.q qVar = (androidx.compose.ui.q) this.d;
                Function0 function02 = (Function0) this.e;
                com.facebook.appevents.g.a((C4114c) this.c, qVar, function02, (InterfaceC0806l) obj, iH6);
                break;
            case 6:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(this.b | 1);
                androidx.compose.ui.q qVar2 = (androidx.compose.ui.q) this.d;
                C0861v c0861v = (C0861v) this.e;
                com.facebook.appevents.m.l((kotlinx.collections.immutable.b) this.c, qVar2, c0861v, (InterfaceC0806l) obj, iH7);
                break;
            case 7:
                ((Integer) obj2).getClass();
                int iH8 = C0776c.H(1);
                androidx.compose.ui.q qVar3 = (androidx.compose.ui.q) this.e;
                com.facebook.appevents.iap.u.a((com.quizlet.features.achievements.data.h) this.c, (Function1) this.d, qVar3, (InterfaceC0806l) obj, iH8, this.b);
                break;
            case 8:
                ((Integer) obj2).getClass();
                int iH9 = C0776c.H(this.b | 1);
                androidx.compose.ui.n nVar2 = (androidx.compose.ui.n) this.d;
                Function1 function13 = (Function1) this.e;
                com.google.android.exoplayer2.drm.b.a((C4166t) this.c, nVar2, function13, (InterfaceC0806l) obj, iH9);
                break;
            case 9:
                ((Integer) obj2).getClass();
                int iH10 = C0776c.H(this.b | 1);
                androidx.compose.ui.n nVar3 = (androidx.compose.ui.n) this.d;
                Function1 function14 = (Function1) this.e;
                AbstractC3053s1.a((kotlinx.collections.immutable.b) this.c, nVar3, function14, (InterfaceC0806l) obj, iH10);
                break;
            case 10:
                ((Integer) obj2).intValue();
                int iH11 = C0776c.H(this.b | 1);
                AbstractC3253s0.e((com.quizlet.features.infra.models.flashcards.j) this.c, (Function1) this.d, (Function0) this.e, (InterfaceC0806l) obj, iH11);
                break;
            case 11:
                ((Integer) obj2).getClass();
                int iH12 = C0776c.H(this.b | 1);
                androidx.compose.ui.n nVar4 = (androidx.compose.ui.n) this.d;
                Function1 function15 = (Function1) this.e;
                AbstractC3133e5.b((com.quizlet.features.home.data.u) this.c, nVar4, function15, (InterfaceC0806l) obj, iH12);
                break;
            case 12:
                ((Integer) obj2).getClass();
                int iH13 = C0776c.H(this.b | 1);
                androidx.compose.ui.q qVar4 = (androidx.compose.ui.q) this.d;
                Function0 function03 = (Function0) this.e;
                AbstractC3169i5.a((v2) this.c, qVar4, function03, (InterfaceC0806l) obj, iH13);
                break;
            case 13:
                ((Integer) obj2).getClass();
                int iH14 = C0776c.H(this.b | 1);
                com.quizlet.assembly.compose.modals.x xVar2 = (com.quizlet.assembly.compose.modals.x) this.d;
                Function0 function04 = (Function0) this.e;
                L5.c((com.quizlet.assembly.compose.modals.x) this.c, xVar2, function04, (InterfaceC0806l) obj, iH14);
                break;
            case 14:
                ((Integer) obj2).getClass();
                int iH15 = C0776c.H(1);
                Function1 function16 = (Function1) this.e;
                S5.b((com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.q) this.c, (androidx.compose.ui.q) this.d, function16, (InterfaceC0806l) obj, iH15, this.b);
                break;
            case 15:
                ((Integer) obj2).getClass();
                int iH16 = C0776c.H(this.b | 1);
                com.quizlet.features.infra.snackbar.composables.a aVar = (com.quizlet.features.infra.snackbar.composables.a) this.d;
                androidx.compose.ui.q qVar5 = (androidx.compose.ui.q) this.e;
                J6.a((L3) this.c, aVar, qVar5, (InterfaceC0806l) obj, iH16);
                break;
            case 16:
                ((Integer) obj2).getClass();
                int iH17 = C0776c.H(1);
                com.quizlet.features.notes.data.f fVar = (com.quizlet.features.notes.data.f) this.c;
                Function1 function17 = (Function1) this.e;
                int i2 = this.b;
                X6.a(fVar, (androidx.compose.ui.q) this.d, function17, i2, (InterfaceC0806l) obj, iH17);
                break;
            case 17:
                ((Integer) obj2).getClass();
                int iH18 = C0776c.H(this.b | 1);
                Function0 function05 = (Function0) this.d;
                Function1 function18 = (Function1) this.e;
                AbstractC3171i7.c((com.quizlet.features.notes.detail.states.d) this.c, function05, function18, (InterfaceC0806l) obj, iH18);
                break;
            case 18:
                ((Integer) obj2).getClass();
                int iH19 = C0776c.H(this.b | 1);
                androidx.compose.ui.q qVar6 = (androidx.compose.ui.q) this.d;
                androidx.compose.runtime.internal.d dVar2 = (androidx.compose.runtime.internal.d) this.e;
                AbstractC3189k7.a((String) this.c, qVar6, dVar2, (InterfaceC0806l) obj, iH19);
                break;
            case 19:
                ((Integer) obj2).getClass();
                M7.b(C0776c.H(this.b | 1), (InterfaceC0806l) obj, (m2) this.c, (Function0) this.d, (Function0) this.e);
                break;
            case 20:
                ((Integer) obj2).getClass();
                int iH20 = C0776c.H(this.b | 1);
                Function1 function19 = (Function1) this.d;
                androidx.compose.ui.n nVar5 = (androidx.compose.ui.n) this.e;
                AbstractC3409x1.a((com.quizlet.features.onboarding.ell.v) this.c, function19, nVar5, (InterfaceC0806l) obj, iH20);
                break;
            case 21:
                ((Integer) obj2).intValue();
                int iH21 = C0776c.H(this.b | 1);
                AbstractC3409x1.b((com.quizlet.features.onboarding.ell.v) this.c, (com.quizlet.features.onboarding.ell.m) this.d, (Function1) this.e, (InterfaceC0806l) obj, iH21);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                ((Integer) obj2).intValue();
                int iH22 = C0776c.H(this.b | 1);
                G1.b((com.quizlet.features.onboarding.survey.n) this.c, (Function1) this.d, (z0) this.e, (InterfaceC0806l) obj, iH22);
                break;
            case EventType.AUDIO /* 23 */:
                ((Integer) obj2).intValue();
                int iH23 = C0776c.H(this.b | 1);
                G1.d((com.quizlet.features.onboarding.survey.m) this.c, (com.quizlet.features.onboarding.survey.n) this.d, (Function1) this.e, (InterfaceC0806l) obj, iH23);
                break;
            case EventType.VIDEO /* 24 */:
                ((Integer) obj2).getClass();
                int iH24 = C0776c.H(this.b | 1);
                K1.a((com.quizlet.features.paywall.state.c) this.c, (Function0) this.d, (Function0) this.e, (InterfaceC0806l) obj, iH24);
                break;
            case EventType.SUBS /* 25 */:
                ((Integer) obj2).intValue();
                int iH25 = C0776c.H(this.b | 1);
                N1.c((androidx.compose.ui.text.input.A) this.c, (Function0) this.d, (Function1) this.e, (InterfaceC0806l) obj, iH25);
                break;
            case EventType.CDN /* 26 */:
                ((Integer) obj2).intValue();
                int iH26 = C0776c.H(this.b | 1);
                AbstractC3394t2.b((com.quizlet.assembly.compose.modals.x) this.c, (com.quizlet.features.practicetest.takingtest.data.M) this.d, (Function1) this.e, (InterfaceC0806l) obj, iH26);
                break;
            case 27:
                ((Integer) obj2).intValue();
                int iH27 = C0776c.H(this.b | 1);
                com.quizlet.features.questionnaire.screens.l.d((com.quizlet.features.questionnaire.navigation.b) this.c, (androidx.navigation.H) this.d, (Function0) this.e, (InterfaceC0806l) obj, iH27);
                break;
            case 28:
                ((Integer) obj2).getClass();
                int iH28 = C0776c.H(1);
                com.quizlet.features.questiontypes.composables.d dVar3 = (com.quizlet.features.questiontypes.composables.d) this.e;
                G2.a((com.quizlet.features.questiontypes.composables.d) this.c, (androidx.compose.ui.q) this.d, dVar3, (InterfaceC0806l) obj, iH28, this.b);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH29 = C0776c.H(this.b | 1);
                C0995g c0995g = (C0995g) this.c;
                androidx.compose.runtime.internal.d dVar4 = (androidx.compose.runtime.internal.d) this.e;
                R2.b(c0995g, (androidx.compose.ui.q) this.d, dVar4, (InterfaceC0806l) obj, iH29);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ u(int i, int i2, int i3, Object obj, Object obj2, Object obj3) {
        this.a = i3;
        this.c = obj;
        this.d = obj2;
        this.e = obj3;
        this.b = i2;
    }

    public /* synthetic */ u(int i, int i2, Object obj, Object obj2, Object obj3) {
        this.a = i2;
        this.c = obj;
        this.d = obj2;
        this.e = obj3;
        this.b = i;
    }
}
