package com.quizlet.features.achievements.ui.composables;

import androidx.compose.foundation.layout.z0;
import androidx.compose.foundation.pager.C0466e;
import androidx.compose.material3.O3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0995g;
import androidx.transition.C1405h;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3142f5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3191l0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3243q7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3267t6;
import com.google.android.gms.internal.mlkit_vision_barcode.B0;
import com.google.android.gms.internal.mlkit_vision_barcode.N4;
import com.google.android.gms.internal.mlkit_vision_barcode.V4;
import com.google.android.gms.internal.mlkit_vision_camera.L2;
import com.google.android.gms.internal.mlkit_vision_camera.R2;
import com.google.android.gms.internal.mlkit_vision_camera.p3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3467i;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3537t4;
import com.google.android.gms.internal.mlkit_vision_common.X2;
import com.google.android.gms.internal.mlkit_vision_common.X3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3626g5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E4;
import com.quizlet.data.model.EnumC4159q0;
import com.quizlet.data.model.m2;
import com.quizlet.data.model.v2;
import com.quizlet.db.data.models.persisted.DBDiagramShape;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4739h;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.StudiableText;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class p implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ int d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;

    public /* synthetic */ p(int i, com.quizlet.learn.data.A a, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, Function0 function03, int i2) {
        this.a = 15;
        this.d = i;
        this.e = a;
        this.f = qVar;
        this.g = function0;
        this.c = function02;
        this.b = function03;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.d | 1);
                androidx.compose.ui.n nVar = (androidx.compose.ui.n) this.c;
                Function1 function1 = (Function1) this.b;
                com.facebook.appevents.ml.f.a((kotlinx.collections.immutable.b) this.e, (kotlinx.collections.immutable.b) this.f, (kotlinx.collections.immutable.b) this.g, nVar, function1, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.d | 1);
                com.quizlet.features.folders.addtofolder.data.u uVar = (com.quizlet.features.folders.addtofolder.data.u) this.e;
                Function0 function0 = (Function0) this.g;
                androidx.compose.ui.n nVar2 = (androidx.compose.ui.n) this.c;
                B0.d(uVar, (Function1) this.b, (Function0) this.f, function0, nVar2, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.d | 1);
                kotlinx.collections.immutable.e eVar = (kotlinx.collections.immutable.e) this.f;
                com.quizlet.features.folders.edittags.viewmodel.c cVar = (com.quizlet.features.folders.edittags.viewmodel.c) this.g;
                V4.c((com.quizlet.assembly.compose.modals.x) this.e, (androidx.compose.ui.n) this.c, (Function1) this.b, eVar, cVar, (InterfaceC0806l) obj, iH3);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(1);
                Function0 function02 = (Function0) this.c;
                V4.d((String) this.e, (Function1) this.b, (EnumC4159q0) this.f, (androidx.compose.ui.q) this.g, function02, (InterfaceC0806l) obj, iH4, this.d);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.d | 1);
                Function0 function03 = (Function0) this.c;
                Function0 function04 = (Function0) this.b;
                AbstractC3142f5.b((v2) this.e, (androidx.compose.ui.q) this.f, (Function0) this.g, function03, function04, (InterfaceC0806l) obj, iH5);
                break;
            case 5:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(this.d | 1);
                O3 o3 = (O3) this.g;
                Function2 function2 = (Function2) this.b;
                AbstractC3267t6.g((androidx.compose.ui.n) this.c, (com.quizlet.features.infra.folder.tag.viewmodel.a) this.e, (com.quizlet.assembly.compose.modals.x) this.f, o3, function2, (InterfaceC0806l) obj, iH6);
                break;
            case 6:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(this.d | 1);
                com.quizlet.features.infra.folder.tag.screenstates.k kVar = (com.quizlet.features.infra.folder.tag.screenstates.k) this.g;
                Function1 function12 = (Function1) this.b;
                AbstractC3267t6.f((O3) this.e, (androidx.compose.ui.n) this.c, (com.quizlet.assembly.compose.modals.x) this.f, kVar, function12, (InterfaceC0806l) obj, iH7);
                break;
            case 7:
                ((Integer) obj2).getClass();
                int iH8 = C0776c.H(this.d | 1);
                Function2 function22 = (Function2) this.g;
                z0 z0Var = (z0) this.c;
                AbstractC3243q7.a((com.quizlet.features.notes.detail.states.g) this.e, (Function1) this.b, (androidx.compose.ui.q) this.f, function22, z0Var, (InterfaceC0806l) obj, iH8);
                break;
            case 8:
                ((Integer) obj2).getClass();
                int iH9 = C0776c.H(this.d | 1);
                com.quizlet.features.practicetest.results.data.d dVar = (com.quizlet.features.practicetest.results.data.d) this.f;
                String str = (String) this.c;
                androidx.compose.ui.q qVar = (androidx.compose.ui.q) this.b;
                C1405h.a((String) this.e, dVar, (String) this.g, str, qVar, (InterfaceC0806l) obj, iH9);
                break;
            case 9:
                ((Integer) obj2).getClass();
                int iH10 = C0776c.H(this.d | 1);
                Function0 function05 = (Function0) this.c;
                Function0 function06 = (Function0) this.b;
                L2.a((com.quizlet.features.questiontypes.data.d) this.e, (androidx.compose.ui.q) this.f, (Function0) this.g, function05, function06, (InterfaceC0806l) obj, iH10);
                break;
            case 10:
                ((Integer) obj2).getClass();
                int iH11 = C0776c.H(this.d | 1);
                C0995g c0995g = (C0995g) this.e;
                Function1 function13 = (Function1) this.g;
                androidx.compose.ui.q qVar2 = (androidx.compose.ui.q) this.c;
                R2.a(c0995g, (com.quizlet.features.questiontypes.fitb.ui.e) this.f, (Function1) this.b, function13, qVar2, (InterfaceC0806l) obj, iH11);
                break;
            case 11:
                ((Integer) obj2).getClass();
                int iH12 = C0776c.H(this.d | 1);
                Function0 function07 = (Function0) this.c;
                Function1 function14 = (Function1) this.b;
                p3.b((StudiableText) this.e, (StudiableAudio) this.f, (androidx.compose.ui.q) this.g, function07, function14, (InterfaceC0806l) obj, iH12);
                break;
            case 12:
                ((Integer) obj2).getClass();
                int iH13 = C0776c.H(this.d | 1);
                com.quizlet.features.questiontypes.written.q qVar3 = (com.quizlet.features.questiontypes.written.q) this.e;
                com.quizlet.features.questiontypes.written.a aVar = (com.quizlet.features.questiontypes.written.a) this.g;
                com.quizlet.features.questiontypes.basequestion.i iVar = (com.quizlet.features.questiontypes.basequestion.i) this.c;
                androidx.compose.ui.q qVar4 = (androidx.compose.ui.q) this.b;
                AbstractC3467i.d(qVar3, (com.quizlet.features.questiontypes.basequestion.data.a) this.f, aVar, iVar, qVar4, (InterfaceC0806l) obj, iH13);
                break;
            case 13:
                ((Integer) obj2).getClass();
                int iH14 = C0776c.H(this.d | 1);
                Function0 function08 = (Function0) this.c;
                Function1 function15 = (Function1) this.b;
                X2.c((com.quizlet.features.settings.data.states.l) this.e, (String) this.f, (Function0) this.g, function08, function15, (InterfaceC0806l) obj, iH14);
                break;
            case 14:
                ((Integer) obj2).getClass();
                int iH15 = C0776c.H(this.d | 1);
                m2 m2Var = (m2) this.f;
                Function0 function09 = (Function0) this.g;
                Function0 function010 = (Function0) this.b;
                X3.a((com.quizlet.assembly.compose.modals.x) this.e, m2Var, (androidx.compose.ui.n) this.c, function09, function010, (InterfaceC0806l) obj, iH15);
                break;
            case 15:
                ((Integer) obj2).getClass();
                int iH16 = C0776c.H(1);
                Function0 function011 = (Function0) this.c;
                Function0 function012 = (Function0) this.b;
                AbstractC3537t4.c(this.d, (com.quizlet.learn.data.A) this.e, (androidx.compose.ui.q) this.f, (Function0) this.g, function011, function012, (InterfaceC0806l) obj, iH16);
                break;
            case 16:
                ((Integer) obj2).getClass();
                int iH17 = C0776c.H(this.d | 1);
                com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar2 = (com.quizlet.quizletandroid.ui.globalnav.navigation.a) this.c;
                Function1 function16 = (Function1) this.b;
                E4.a((androidx.navigation.H) this.e, (L) this.f, (C4739h) this.g, aVar2, function16, (InterfaceC0806l) obj, iH17);
                break;
            case 17:
                ((Integer) obj2).getClass();
                int iH18 = C0776c.H(this.d | 1);
                androidx.fragment.app.I i = (androidx.fragment.app.I) this.e;
                androidx.navigation.H h = (androidx.navigation.H) this.c;
                Function1 function17 = (Function1) this.b;
                E4.c(i, (L) this.f, (com.quizlet.quizletandroid.ui.globalnav.navigation.a) this.g, h, function17, (InterfaceC0806l) obj, iH18);
                break;
            case 18:
                ((Integer) obj2).getClass();
                int iH19 = C0776c.H(this.d | 1);
                Function1 function18 = (Function1) this.g;
                Function1 function19 = (Function1) this.c;
                AbstractC3626g5.a((kotlinx.collections.immutable.b) this.e, (Function1) this.b, (Function1) this.f, function18, function19, (InterfaceC0806l) obj, iH19);
                break;
            case 19:
                ((Integer) obj2).getClass();
                int iH20 = C0776c.H(this.d | 1);
                DiagramData diagramData = (DiagramData) this.e;
                androidx.compose.ui.q qVar5 = (androidx.compose.ui.q) this.c;
                Function1 function110 = (Function1) this.b;
                com.quizlet.quizletandroid.ui.studymodes.testmode.compose.p.a(diagramData, (DBDiagramShape) this.f, (DBDiagramShape) this.g, qVar5, function110, (InterfaceC0806l) obj, iH20);
                break;
            case 20:
                ((Integer) obj2).getClass();
                int iH21 = C0776c.H(this.d | 1);
                androidx.compose.ui.q qVar6 = (androidx.compose.ui.q) this.c;
                com.google.mlkit.common.model.a.e((String) this.e, (C0466e) this.f, (kotlinx.collections.immutable.e) this.g, (Function1) this.b, qVar6, (InterfaceC0806l) obj, iH21);
                break;
            case 21:
                ((Integer) obj2).getClass();
                int iH22 = C0776c.H(this.d | 1);
                com.quizlet.search.data.c cVar2 = (com.quizlet.search.data.c) this.e;
                androidx.compose.ui.q qVar7 = (androidx.compose.ui.q) this.c;
                Function1 function111 = (Function1) this.b;
                AbstractC3191l0.b(cVar2, (String) this.f, (String) this.g, qVar7, function111, (InterfaceC0806l) obj, iH22);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH23 = C0776c.H(this.d | 1);
                Function0 function013 = (Function0) this.c;
                androidx.compose.ui.q qVar8 = (androidx.compose.ui.q) this.b;
                N4.c((String) this.e, (String) this.f, (com.quizlet.security.challenge.viewmodel.a) this.g, function013, qVar8, (InterfaceC0806l) obj, iH23);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ p(O3 o3, androidx.compose.ui.n nVar, com.quizlet.assembly.compose.modals.x xVar, com.quizlet.features.infra.folder.tag.screenstates.k kVar, Function1 function1, int i) {
        this.a = 6;
        this.e = o3;
        this.c = nVar;
        this.f = xVar;
        this.g = kVar;
        this.b = function1;
        this.d = i;
    }

    public /* synthetic */ p(androidx.compose.ui.n nVar, com.quizlet.features.infra.folder.tag.viewmodel.a aVar, com.quizlet.assembly.compose.modals.x xVar, O3 o3, Function2 function2, int i) {
        this.a = 5;
        this.c = nVar;
        this.e = aVar;
        this.f = xVar;
        this.g = o3;
        this.b = function2;
        this.d = i;
    }

    public /* synthetic */ p(C0995g c0995g, com.quizlet.features.questiontypes.fitb.ui.e eVar, Function1 function1, Function1 function12, androidx.compose.ui.q qVar, int i) {
        this.a = 10;
        this.e = c0995g;
        this.f = eVar;
        this.b = function1;
        this.g = function12;
        this.c = qVar;
        this.d = i;
    }

    public /* synthetic */ p(com.quizlet.assembly.compose.modals.x xVar, androidx.compose.ui.n nVar, Function1 function1, kotlinx.collections.immutable.e eVar, com.quizlet.features.folders.edittags.viewmodel.c cVar, int i) {
        this.a = 2;
        this.e = xVar;
        this.c = nVar;
        this.b = function1;
        this.f = eVar;
        this.g = cVar;
        this.d = i;
    }

    public /* synthetic */ p(com.quizlet.assembly.compose.modals.x xVar, m2 m2Var, androidx.compose.ui.n nVar, Function0 function0, Function0 function02, int i) {
        this.a = 14;
        this.e = xVar;
        this.f = m2Var;
        this.c = nVar;
        this.g = function0;
        this.b = function02;
        this.d = i;
    }

    public /* synthetic */ p(Object obj, Object obj2, Object obj3, Object obj4, Object obj5, int i, int i2) {
        this.a = i2;
        this.e = obj;
        this.f = obj2;
        this.g = obj3;
        this.c = obj4;
        this.b = obj5;
        this.d = i;
    }

    public /* synthetic */ p(Object obj, Function1 function1, Object obj2, InterfaceC4938g interfaceC4938g, Object obj3, int i, int i2) {
        this.a = i2;
        this.e = obj;
        this.b = function1;
        this.f = obj2;
        this.g = interfaceC4938g;
        this.c = obj3;
        this.d = i;
    }

    public /* synthetic */ p(String str, C0466e c0466e, kotlinx.collections.immutable.e eVar, Function1 function1, androidx.compose.ui.q qVar, int i) {
        this.a = 20;
        this.e = str;
        this.f = c0466e;
        this.g = eVar;
        this.b = function1;
        this.c = qVar;
        this.d = i;
    }

    public /* synthetic */ p(String str, Function1 function1, EnumC4159q0 enumC4159q0, androidx.compose.ui.q qVar, Function0 function0, int i, int i2) {
        this.a = 3;
        this.e = str;
        this.b = function1;
        this.f = enumC4159q0;
        this.g = qVar;
        this.c = function0;
        this.d = i2;
    }
}
