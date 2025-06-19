package androidx.lifecycle.compose;

import androidx.compose.animation.core.C0247i0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import androidx.compose.ui.text.L;
import androidx.lifecycle.A;
import androidx.lifecycle.J;
import androidx.navigation.C1291m;
import androidx.navigation.U;
import com.comscore.streaming.EventType;
import com.facebook.appevents.iap.u;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3134e6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3142f5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3164i0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3171i7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3209n0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3313z4;
import com.google.android.gms.internal.mlkit_vision_barcode.C4;
import com.google.android.gms.internal.mlkit_vision_barcode.J4;
import com.google.android.gms.internal.mlkit_vision_barcode.M4;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_barcode.S4;
import com.google.android.gms.internal.mlkit_vision_barcode.S5;
import com.google.android.gms.internal.mlkit_vision_barcode.Y6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3413y1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3634h5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3666l5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3674m5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.B5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.F5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.G5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.N5;
import com.quizlet.assembly.compose.buttons.C4089n;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.data.model.C4114c;
import com.quizlet.data.model.EnumC4175w;
import com.quizlet.data.model.EssayInfo;
import com.quizlet.data.model.SimpleImage;
import com.quizlet.explanations.questiondetail.recyclerview.k;
import com.quizlet.explanations.solution.recyclerview.step.i;
import com.quizlet.features.flashcards.S;
import com.quizlet.features.flashcards.settings.l;
import com.quizlet.features.folders.data.K0;
import com.quizlet.features.folders.data.U0;
import com.quizlet.features.infra.folder.create.data.h;
import com.quizlet.ui.models.content.listitem.o;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes.dex */
public final /* synthetic */ class e implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ e(int i, int i2, Object obj, Object obj2, Object obj3) {
        this.a = i2;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(7);
                J j = (J) this.c;
                Function0 function0 = (Function0) this.d;
                AbstractC3413y1.a((A) this.b, j, function0, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                float fFloatValue = ((Float) obj).floatValue();
                ((Float) obj2).getClass();
                E.A((C) this.b, null, null, new androidx.navigation.compose.J(fFloatValue, (C0247i0) this.c, (C1291m) this.d, null), 3);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                q qVar = (q) this.c;
                Function1 function1 = (Function1) this.d;
                AbstractC3634h5.f((C4089n) this.b, qVar, function1, (InterfaceC0806l) obj, iH2);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(1);
                n nVar = (n) this.c;
                Function1 function12 = (Function1) this.d;
                AbstractC3666l5.a((com.quizlet.ui.models.content.carditem.c) this.b, nVar, function12, (InterfaceC0806l) obj, iH3);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(1);
                n nVar2 = (n) this.c;
                Function1 function13 = (Function1) this.d;
                AbstractC3674m5.a((com.quizlet.ui.models.content.carditem.d) this.b, nVar2, function13, (InterfaceC0806l) obj, iH4);
                break;
            case 5:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(1);
                n nVar3 = (n) this.c;
                L l = (L) this.d;
                B5.e((String) this.b, nVar3, l, (InterfaceC0806l) obj, iH5);
                break;
            case 6:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(1);
                Function1 function14 = (Function1) this.c;
                n nVar4 = (n) this.d;
                F5.b((com.quizlet.assembly.compose.menu.q) this.b, function14, nVar4, (InterfaceC0806l) obj, iH6);
                break;
            case 7:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(1);
                q qVar2 = (q) this.c;
                L l2 = (L) this.d;
                G5.a((String) this.b, qVar2, l2, (InterfaceC0806l) obj, iH7);
                break;
            case 8:
                ((Integer) obj2).getClass();
                int iH8 = C0776c.H(1);
                x xVar = (x) this.c;
                Function2 function2 = (Function2) this.d;
                N5.c((com.quizlet.assembly.compose.menu.q) this.b, xVar, function2, (InterfaceC0806l) obj, iH8);
                break;
            case 9:
                ((Integer) obj2).getClass();
                int iH9 = C0776c.H(49);
                k.a((SimpleImage) this.b, (Function0) this.d, (q) this.c, (InterfaceC0806l) obj, iH9);
                break;
            case 10:
                ((Integer) obj2).getClass();
                int iH10 = C0776c.H(1);
                q qVar3 = (q) this.c;
                U u = (U) this.d;
                i.g((com.quizlet.explanations.solution.recyclerview.step.e) this.b, qVar3, u, (InterfaceC0806l) obj, iH10);
                break;
            case 11:
                ((Integer) obj2).getClass();
                int iH11 = C0776c.H(385);
                i.a((com.quizlet.qutils.string.f) this.b, (com.quizlet.qutils.string.f) this.c, (q) this.d, (InterfaceC0806l) obj, iH11);
                break;
            case 12:
                ((Integer) obj2).getClass();
                int iH12 = C0776c.H(9);
                C4114c c4114c = (C4114c) this.c;
                n nVar5 = (n) this.d;
                com.bumptech.glide.c.a((x) this.b, c4114c, nVar5, (InterfaceC0806l) obj, iH12);
                break;
            case 13:
                ((Integer) obj2).getClass();
                int iH13 = C0776c.H(1);
                q qVar4 = (q) this.c;
                Function1 function15 = (Function1) this.d;
                u.b((com.quizlet.features.achievements.data.e) this.b, qVar4, function15, (InterfaceC0806l) obj, iH13);
                break;
            case 14:
                ((Integer) obj2).getClass();
                int iH14 = C0776c.H(1);
                com.facebook.appevents.internal.d.a((C4114c) this.b, (com.quizlet.features.achievements.achievement.g) this.c, (n) this.d, (InterfaceC0806l) obj, iH14);
                break;
            case 15:
                ((Integer) obj2).getClass();
                int iH15 = C0776c.H(1);
                Function1 function16 = (Function1) this.b;
                com.quizlet.features.achievements.viewmodel.c cVar = (com.quizlet.features.achievements.viewmodel.c) this.c;
                com.google.android.gms.common.wrappers.a.a((Function0) this.d, function16, cVar, (InterfaceC0806l) obj, iH15);
                break;
            case 16:
                ((Integer) obj2).getClass();
                int iH16 = C0776c.H(1);
                AbstractC3164i0.a((com.quizlet.features.flashcards.data.q) this.b, (q) this.c, (Function0) this.d, (InterfaceC0806l) obj, iH16);
                break;
            case 17:
                ((Integer) obj2).getClass();
                int iH17 = C0776c.H(1);
                S s = (S) this.b;
                l lVar = (l) this.c;
                AbstractC3209n0.b((Function0) this.d, s, lVar, (InterfaceC0806l) obj, iH17);
                break;
            case 18:
                ((Integer) obj2).getClass();
                int iH18 = C0776c.H(9);
                q qVar5 = (q) this.c;
                Function1 function17 = (Function1) this.d;
                AbstractC3313z4.a((com.quizlet.features.folders.changetags.data.f) this.b, qVar5, function17, (InterfaceC0806l) obj, iH18);
                break;
            case 19:
                ((Integer) obj2).getClass();
                C4.a(C0776c.H(9), (InterfaceC0806l) obj, (n) this.c, (x) this.b, (Function0) this.d);
                break;
            case 20:
                ((Integer) obj2).getClass();
                int iH19 = C0776c.H(1);
                h hVar = (h) this.c;
                Function0 function02 = (Function0) this.d;
                J4.a((n) this.b, hVar, function02, (InterfaceC0806l) obj, iH19);
                break;
            case 21:
                ((Integer) obj2).getClass();
                int iH20 = C0776c.H(1);
                M4.a((K0) this.b, (n) this.c, (Function0) this.d, (InterfaceC0806l) obj, iH20);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                ((Integer) obj2).getClass();
                int iH21 = C0776c.H(1);
                Function1 function18 = (Function1) this.c;
                n nVar6 = (n) this.d;
                S4.e((U0) this.b, function18, nVar6, (InterfaceC0806l) obj, iH21);
                break;
            case EventType.AUDIO /* 23 */:
                ((Integer) obj2).getClass();
                int iH22 = C0776c.H(1);
                q qVar6 = (q) this.c;
                Function0 function03 = (Function0) this.d;
                AbstractC3142f5.c((com.quizlet.features.home.viewmodel.e) this.b, qVar6, function03, (InterfaceC0806l) obj, iH22);
                break;
            case EventType.VIDEO /* 24 */:
                ((Integer) obj2).getClass();
                int iH23 = C0776c.H(1);
                Function0 function04 = (Function0) this.d;
                q qVar7 = (q) this.c;
                AbstractC3178j5.d((o) this.b, function04, qVar7, (InterfaceC0806l) obj, iH23);
                break;
            case EventType.SUBS /* 25 */:
                ((Integer) obj2).getClass();
                int iH24 = C0776c.H(1);
                q qVar8 = (q) this.c;
                Function1 function19 = (Function1) this.d;
                P5.d((com.quizlet.features.infra.models.folders.c) this.b, qVar8, function19, (InterfaceC0806l) obj, iH24);
                break;
            case EventType.CDN /* 26 */:
                ((Integer) obj2).getClass();
                int iH25 = C0776c.H(1);
                q qVar9 = (q) this.c;
                Function0 function05 = (Function0) this.d;
                S5.a((Function1) this.b, qVar9, function05, (InterfaceC0806l) obj, iH25);
                break;
            case 27:
                ((Integer) obj2).getClass();
                int iH26 = C0776c.H(1);
                n nVar7 = (n) this.c;
                Function1 function110 = (Function1) this.d;
                AbstractC3134e6.e((com.quizlet.features.infra.folder.menu.data.b) this.b, nVar7, function110, (InterfaceC0806l) obj, iH26);
                break;
            case 28:
                ((Integer) obj2).getClass();
                int iH27 = C0776c.H(1);
                q qVar10 = (q) this.c;
                Function0 function06 = (Function0) this.d;
                Y6.a((EnumC4175w) this.b, qVar10, function06, (InterfaceC0806l) obj, iH27);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH28 = C0776c.H(1);
                String str = (String) this.c;
                q qVar11 = (q) this.d;
                AbstractC3171i7.a((EssayInfo) this.b, str, qVar11, (InterfaceC0806l) obj, iH28);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ e(Object obj, Function0 function0, q qVar, int i, int i2) {
        this.a = i2;
        this.b = obj;
        this.d = function0;
        this.c = qVar;
    }

    public /* synthetic */ e(Function0 function0, Object obj, Object obj2, int i, int i2) {
        this.a = i2;
        this.d = function0;
        this.b = obj;
        this.c = obj2;
    }

    public /* synthetic */ e(C c, C0247i0 c0247i0, C1291m c1291m) {
        this.a = 1;
        this.b = c;
        this.c = c0247i0;
        this.d = c1291m;
    }
}
