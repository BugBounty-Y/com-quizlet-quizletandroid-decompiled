package com.quizlet.assembly.compose.menu;

import androidx.compose.foundation.layout.A0;
import androidx.compose.foundation.layout.z0;
import androidx.compose.material3.L3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.L;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.A6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3108b7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3143f6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3173j0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3179j6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3187k5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3253s0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3259s6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3269u0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3313z4;
import com.google.android.gms.internal.mlkit_vision_barcode.B0;
import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3348i;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3402v2;
import com.google.android.gms.internal.mlkit_vision_camera.C2;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import com.google.android.gms.internal.mlkit_vision_camera.m3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3561x4;
import com.google.android.gms.internal.mlkit_vision_common.B4;
import com.google.android.gms.internal.mlkit_vision_common.C4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3621g0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.G5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.N5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.features.practicetest.detail.data.F;
import com.quizlet.studiablemodels.StudiableText;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class i implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;

    public /* synthetic */ i(int i, D6 d6, Function0 function0, Function1 function1, Function1 function12, int i2) {
        this.a = 22;
        this.b = i;
        this.c = d6;
        this.d = function0;
        this.f = function1;
        this.e = function12;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.b | 1);
                L l = (L) this.e;
                Function1 function1 = (Function1) this.f;
                G5.b((o) this.c, (androidx.compose.ui.q) this.d, l, function1, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                N5.a((s) this.c, (x) this.d, (Function2) this.e, (Function0) this.f, (InterfaceC0806l) obj, C0776c.H(this.b | 1));
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.b | 1);
                Function1 function12 = (Function1) this.f;
                Function0 function0 = (Function0) this.e;
                com.google.common.util.concurrent.b.f(iH2, (InterfaceC0806l) obj, (androidx.compose.ui.q) this.d, (String) this.c, function0, function12);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.b | 1);
                androidx.compose.ui.n nVar = (androidx.compose.ui.n) this.e;
                Function1 function13 = (Function1) this.f;
                com.google.android.gms.dynamite.d.a((kotlinx.collections.immutable.b) this.c, (kotlinx.collections.immutable.b) this.d, nVar, function13, (InterfaceC0806l) obj, iH3);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(this.b | 1);
                Function0 function02 = (Function0) this.e;
                Function0 function03 = (Function0) this.f;
                com.quizlet.features.emailconfirmation.ui.composables.q.e((com.quizlet.features.emailconfirmation.ui.composables.r) this.c, (androidx.compose.ui.q) this.d, function02, function03, (InterfaceC0806l) obj, iH4);
                break;
            case 5:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.b | 1);
                com.quizlet.features.flashcards.data.q qVar = (com.quizlet.features.flashcards.data.q) this.c;
                Function0 function04 = (Function0) this.e;
                Function0 function05 = (Function0) this.f;
                AbstractC3173j0.a(qVar, (androidx.compose.ui.q) this.d, function04, function05, (InterfaceC0806l) obj, iH5);
                break;
            case 6:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(this.b | 1);
                Function0 function06 = (Function0) this.e;
                androidx.compose.ui.q qVar2 = (androidx.compose.ui.q) this.d;
                AbstractC3253s0.f((StudiableText) this.c, (Function1) this.f, function06, qVar2, (InterfaceC0806l) obj, iH6);
                break;
            case 7:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(this.b | 1);
                String str = (String) this.f;
                androidx.compose.ui.q qVar3 = (androidx.compose.ui.q) this.d;
                AbstractC3269u0.b((C0995g) this.c, (androidx.compose.ui.graphics.painter.b) this.e, str, qVar3, (InterfaceC0806l) obj, iH7);
                break;
            case 8:
                ((Integer) obj2).getClass();
                int iH8 = C0776c.H(this.b | 1);
                androidx.compose.ui.q qVar4 = (androidx.compose.ui.q) this.d;
                Function0 function07 = (Function0) this.e;
                B0.e((kotlinx.collections.immutable.b) this.c, (Function1) this.f, qVar4, function07, (InterfaceC0806l) obj, iH8);
                break;
            case 9:
                ((Integer) obj2).getClass();
                int iH9 = C0776c.H(this.b | 1);
                Function1 function14 = (Function1) this.f;
                com.quizlet.features.folders.changetags.viewmodel.e eVar = (com.quizlet.features.folders.changetags.viewmodel.e) this.e;
                AbstractC3313z4.c((x) this.c, (androidx.compose.ui.n) this.d, function14, eVar, (InterfaceC0806l) obj, iH9);
                break;
            case 10:
                ((Integer) obj2).getClass();
                int iH10 = C0776c.H(this.b | 1);
                Function1 function15 = (Function1) this.f;
                androidx.compose.ui.q qVar5 = (androidx.compose.ui.q) this.d;
                AbstractC3187k5.a((kotlinx.collections.immutable.e) this.c, (Function0) this.e, function15, qVar5, (InterfaceC0806l) obj, iH10);
                break;
            case 11:
                ((Integer) obj2).getClass();
                int iH11 = C0776c.H(this.b | 1);
                Function1 function16 = (Function1) this.f;
                androidx.compose.ui.q qVar6 = (androidx.compose.ui.q) this.d;
                AbstractC3143f6.a((L3) this.c, (com.quizlet.features.infra.folder.menu.composable.i) this.e, function16, qVar6, (InterfaceC0806l) obj, iH11);
                break;
            case 12:
                ((Integer) obj2).getClass();
                int iH12 = C0776c.H(this.b | 1);
                Function1 function17 = (Function1) this.f;
                androidx.compose.ui.q qVar7 = (androidx.compose.ui.q) this.d;
                AbstractC3179j6.a((com.quizlet.features.infra.folder.menu.data.b) this.c, (kotlinx.collections.immutable.c) this.e, function17, qVar7, (InterfaceC0806l) obj, iH12);
                break;
            case 13:
                ((Integer) obj2).getClass();
                int iH13 = C0776c.H(this.b | 1);
                Function1 function18 = (Function1) this.f;
                androidx.compose.ui.q qVar8 = (androidx.compose.ui.q) this.d;
                AbstractC3242q6.b((x) this.c, (kotlinx.collections.immutable.b) this.e, function18, qVar8, (InterfaceC0806l) obj, iH13);
                break;
            case 14:
                ((Integer) obj2).getClass();
                int iH14 = C0776c.H(this.b | 1);
                com.quizlet.features.infra.folder.tag.screenstates.k kVar = (com.quizlet.features.infra.folder.tag.screenstates.k) this.e;
                androidx.compose.ui.q qVar9 = (androidx.compose.ui.q) this.d;
                AbstractC3259s6.c((Function1) this.f, (String) this.c, kVar, qVar9, (InterfaceC0806l) obj, iH14);
                break;
            case 15:
                ((Integer) obj2).getClass();
                int iH15 = C0776c.H(this.b | 1);
                Function0 function08 = (Function0) this.e;
                Function0 function09 = (Function0) this.f;
                A6.a((String) this.c, (x) this.d, function08, function09, (InterfaceC0806l) obj, iH15);
                break;
            case 16:
                ((Integer) obj2).getClass();
                int iH16 = C0776c.H(this.b | 1);
                String str2 = (String) this.e;
                androidx.compose.ui.n nVar2 = (androidx.compose.ui.n) this.f;
                AbstractC3108b7.a((x) this.c, (String) this.d, str2, nVar2, (InterfaceC0806l) obj, iH16);
                break;
            case 17:
                ((Integer) obj2).getClass();
                int iH17 = C0776c.H(this.b | 1);
                Function0 function010 = (Function0) this.e;
                Function1 function19 = (Function1) this.f;
                AbstractC3328d.d((com.quizlet.features.notes.upload.states.h) this.c, (Function0) this.d, function010, function19, (InterfaceC0806l) obj, iH17);
                break;
            case 18:
                ((Integer) obj2).getClass();
                int iH18 = C0776c.H(this.b | 1);
                kotlin.jvm.functions.d dVar = (kotlin.jvm.functions.d) this.e;
                Function1 function110 = (Function1) this.f;
                AbstractC3348i.b((com.quizlet.features.notes.upload.states.h) this.c, (Function0) this.d, dVar, function110, (InterfaceC0806l) obj, iH18);
                break;
            case 19:
                ((Integer) obj2).getClass();
                int iH19 = C0776c.H(1);
                androidx.compose.ui.q qVar10 = (androidx.compose.ui.q) this.d;
                int i = this.b;
                W1.G((F) this.c, (Function0) this.e, (Function1) this.f, qVar10, i, (InterfaceC0806l) obj, iH19);
                break;
            case 20:
                ((Integer) obj2).getClass();
                int iH20 = C0776c.H(this.b | 1);
                Function0 function011 = (Function0) this.e;
                androidx.compose.ui.q qVar11 = (androidx.compose.ui.q) this.d;
                AbstractC3402v2.a((Function0) this.c, (Function1) this.f, function011, qVar11, (InterfaceC0806l) obj, iH20);
                break;
            case 21:
                ((Integer) obj2).intValue();
                C2.a((com.quizlet.features.questiontypes.basequestion.data.a) this.c, (com.quizlet.features.questiontypes.basequestion.data.a) this.d, (Function1) this.f, (Function0) this.e, (InterfaceC0806l) obj, C0776c.H(this.b | 1));
                break;
            case EventType.WINDOW_STATE /* 22 */:
                ((Integer) obj2).getClass();
                int iH21 = C0776c.H(1);
                Function1 function111 = (Function1) this.f;
                Function1 function112 = (Function1) this.e;
                m3.a(this.b, (D6) this.c, (Function0) this.d, function111, function112, (InterfaceC0806l) obj, iH21);
                break;
            case EventType.AUDIO /* 23 */:
                ((Integer) obj2).getClass();
                int iH22 = C0776c.H(1);
                Function1 function113 = (Function1) this.f;
                com.quizlet.features.settings.composables.changetheme.a.a((com.quizlet.themes.nighttheme.a) this.c, (androidx.compose.ui.q) this.d, (A0) this.e, function113, (InterfaceC0806l) obj, iH22, this.b);
                break;
            case EventType.VIDEO /* 24 */:
                ((Integer) obj2).getClass();
                int iH23 = C0776c.H(this.b | 1);
                androidx.compose.ui.q qVar12 = (androidx.compose.ui.q) this.d;
                Function1 function114 = (Function1) this.f;
                AbstractC3561x4.c((com.quizlet.learn.data.onboarding.m) this.c, (kotlinx.collections.immutable.e) this.e, qVar12, function114, (InterfaceC0806l) obj, iH23);
                break;
            case EventType.SUBS /* 25 */:
                ((Integer) obj2).getClass();
                B4.b((com.quizlet.learn.ui.progress.g) this.c, (com.quizlet.learn.ui.progress.f) this.e, (Function0) this.f, (androidx.compose.ui.q) this.d, (InterfaceC0806l) obj, C0776c.H(this.b | 1));
                break;
            case EventType.CDN /* 26 */:
                ((Integer) obj2).getClass();
                int iH24 = C0776c.H(this.b | 1);
                Function0 function012 = (Function0) this.e;
                Function0 function013 = (Function0) this.f;
                C4.c(iH24, (InterfaceC0806l) obj, (androidx.compose.ui.q) this.d, (com.quizlet.learn.ui.toolbar.j) this.c, function012, function013);
                break;
            case 27:
                ((Integer) obj2).getClass();
                int iH25 = C0776c.H(this.b | 1);
                Function1 function115 = (Function1) this.f;
                Function0 function014 = (Function0) this.e;
                com.google.android.gms.internal.mlkit_vision_document_scanner.L.g((com.quizlet.login.intro.data.u) this.c, (androidx.compose.ui.q) this.d, function115, function014, (InterfaceC0806l) obj, iH25);
                break;
            case 28:
                ((Integer) obj2).getClass();
                int iH26 = C0776c.H(this.b | 1);
                U.b(iH26, (InterfaceC0806l) obj, (androidx.compose.ui.n) this.f, (String) this.c, (Function0) this.d, (Function0) this.e);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH27 = C0776c.H(this.b | 1);
                z0 z0Var = (z0) this.e;
                Function1 function116 = (Function1) this.f;
                AbstractC3621g0.a((com.quizlet.login.resetpassword.data.g) this.c, (androidx.compose.ui.q) this.d, z0Var, function116, (InterfaceC0806l) obj, iH27);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ i(F f, Function0 function0, Function1 function1, androidx.compose.ui.q qVar, int i, int i2) {
        this.a = 19;
        this.c = f;
        this.e = function0;
        this.f = function1;
        this.d = qVar;
        this.b = i;
    }

    public /* synthetic */ i(com.quizlet.learn.data.onboarding.m mVar, kotlinx.collections.immutable.e eVar, androidx.compose.ui.q qVar, Function1 function1, int i) {
        this.a = 24;
        this.c = mVar;
        this.e = eVar;
        this.d = qVar;
        this.f = function1;
        this.b = i;
    }

    public /* synthetic */ i(com.quizlet.themes.nighttheme.a aVar, androidx.compose.ui.q qVar, A0 a0, Function1 function1, int i, int i2) {
        this.a = 23;
        this.c = aVar;
        this.d = qVar;
        this.e = a0;
        this.f = function1;
        this.b = i2;
    }

    public /* synthetic */ i(Object obj, Object obj2, Object obj3, androidx.compose.ui.q qVar, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.e = obj2;
        this.f = obj3;
        this.d = qVar;
        this.b = i;
    }

    public /* synthetic */ i(Object obj, Object obj2, Object obj3, Object obj4, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.d = obj2;
        this.e = obj3;
        this.f = obj4;
        this.b = i;
    }

    public /* synthetic */ i(Object obj, Object obj2, Function1 function1, Object obj3, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.d = obj2;
        this.f = function1;
        this.e = obj3;
        this.b = i;
    }

    public /* synthetic */ i(Object obj, Function1 function1, Function0 function0, androidx.compose.ui.q qVar, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.f = function1;
        this.e = function0;
        this.d = qVar;
        this.b = i;
    }

    public /* synthetic */ i(Function1 function1, String str, com.quizlet.features.infra.folder.tag.screenstates.k kVar, androidx.compose.ui.q qVar, int i) {
        this.a = 14;
        this.f = function1;
        this.c = str;
        this.e = kVar;
        this.d = qVar;
        this.b = i;
    }

    public /* synthetic */ i(kotlinx.collections.immutable.b bVar, Function1 function1, androidx.compose.ui.q qVar, Function0 function0, int i) {
        this.a = 8;
        this.c = bVar;
        this.f = function1;
        this.d = qVar;
        this.e = function0;
        this.b = i;
    }
}
