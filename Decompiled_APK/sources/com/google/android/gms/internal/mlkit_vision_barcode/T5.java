package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.quizlet.data.model.StudySet;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class T5 {
    public static final void a(androidx.compose.ui.q qVar, Function1 function1, Function1 function12, Function0 function0, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.b bVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.b bVar2;
        com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.b bVar3;
        com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.b bVar4;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-987223387);
        int i3 = i | (c0814p.f(qVar) ? 4 : 2) | (c0814p.h(function1) ? 32 : 16) | (c0814p.h(function12) ? 256 : 128) | (c0814p.h(function0) ? 2048 : 1024) | 8192;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            bVar4 = bVar;
        } else {
            c0814p.S();
            int i4 = i & 1;
            Object obj = C0804k.a;
            if (i4 == 0 || c0814p.w()) {
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                Object objE = AbstractC3417z1.e(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.b bVar5 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.b) objE;
                i2 = i3 & (-57345);
                bVar2 = bVar5;
            } else {
                c0814p.Q();
                i2 = i3 & (-57345);
                bVar2 = bVar;
            }
            c0814p.q();
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o oVar = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o) bVar2;
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(oVar.i, c0814p);
            kotlinx.coroutines.flow.d0 d0Var = oVar.j;
            c0814p.X(198159814);
            boolean z = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI = c0814p.I();
            if (z || objI == obj) {
                objI = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.w(function1, null);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            AbstractC0809m0 abstractC0809m0 = androidx.lifecycle.compose.g.a;
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zH = c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(b) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zH || objI2 == obj) {
                objI2 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.t(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI2);
            c0814p.p(false);
            kotlinx.coroutines.flow.d0 d0Var2 = oVar.k;
            c0814p.X(198162598);
            boolean z2 = (i2 & 896) == 256;
            Object objI3 = c0814p.I();
            if (z2 || objI3 == obj) {
                objI3 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.x(function12, null);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j2 = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            InterfaceC0773a0 interfaceC0773a0D2 = C0776c.D((Function2) objI3, c0814p);
            c0814p.X(1667431386);
            boolean zH2 = c0814p.h(j2) | c0814p.h(d0Var2) | c0814p.f(b) | c0814p.f(interfaceC0773a0D2);
            Object objI4 = c0814p.I();
            if (zH2 || objI4 == obj) {
                objI4 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.v(interfaceC0773a0D2, j2, null, d0Var2);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI4);
            c0814p.p(false);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            mVar.q();
            androidx.compose.ui.q qVarN = androidx.compose.foundation.layout.K0.n(AbstractC0460p.u(AbstractC0382e.v(qVar, f, f), AbstractC0460p.r(c0814p), false, 14), DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.g0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarN);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p, R.string.add_course);
            long jG = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g();
            com.quizlet.themes.e.a(c0814p).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarM = com.quizlet.ui.resources.icons.d.m(c0814p);
            c0814p.X(-1461946116);
            boolean zH3 = c0814p.h(bVar2) | ((i2 & 7168) == 2048);
            Object objI5 = c0814p.I();
            if (zH3 || objI5 == obj) {
                objI5 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.q(bVar2, function0, 0);
                c0814p.i0(objI5);
            }
            c0814p.p(false);
            AbstractC3691o6.c(null, strD, jG, 0L, bVarM, (Function0) objI5, null, null, c0814p, 0, 201);
            androidx.compose.ui.q qVarN2 = androidx.compose.foundation.layout.K0.n(androidx.compose.ui.n.b, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.j0, 7);
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.q qVar2 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.q) interfaceC0773a0G.getValue();
            c0814p.X(-1461936385);
            boolean zH4 = c0814p.h(bVar2);
            Object objI6 = c0814p.I();
            if (zH4 || objI6 == obj) {
                bVar3 = bVar2;
                objI6 = new com.quizlet.explanations.textbook.ui.f(1, bVar3, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.b.class, "onSchoolCourseEvent", "onSchoolCourseEvent(Lcom/quizlet/features/infra/folder/create/coursefolder/schoolcourse/data/SelectSchoolCourseEvent;)V", 0, 23);
                c0814p.i0(objI6);
            } else {
                bVar3 = bVar2;
            }
            c0814p.p(false);
            S5.b(qVar2, qVarN2, (Function1) ((kotlin.reflect.f) objI6), c0814p, 0, 0);
            c0814p = c0814p;
            c0814p.p(true);
            bVar4 = bVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(qVar, function1, function12, function0, bVar4, i);
        }
    }

    public static final long b(float f, float f2) {
        return (Float.floatToRawIntBits(f2) & 4294967295L) | (Float.floatToRawIntBits(f) << 32);
    }

    public static final com.quizlet.ui.models.content.listitem.d c(StudySet studySet, String str, boolean z) {
        Intrinsics.checkNotNullParameter(studySet, "<this>");
        return new com.quizlet.ui.models.content.listitem.d(studySet.n, studySet.a, studySet.h, str, z, !(!studySet.y && (studySet.d > 0 || studySet.B)));
    }
}
