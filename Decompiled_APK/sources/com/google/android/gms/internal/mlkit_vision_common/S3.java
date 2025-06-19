package com.google.android.gms.internal.mlkit_vision_common;

import android.os.Looper;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.C1011l;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U5;
import com.google.android.gms.tasks.Task;
import com.quizlet.features.universaluploadflow.data.C4458g;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class S3 {
    public static final void a(com.quizlet.data.model.m2 m2Var, C4458g c4458g, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1264602354);
        int i2 = i | (c0814p2.f(m2Var) ? 4 : 2) | (c0814p2.f(c4458g) ? 32 : 16) | (c0814p2.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            mVar.p();
            androidx.compose.ui.q qVarV = AbstractC0382e.v(nVar, f, com.quizlet.ui.resources.designsystem.generated.j.j);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p2, 0);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVarV);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, bA, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p2, i3, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p2, R.string.uuf_upload_guidelines), null, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).e, c0814p2, 0, 0, 65534);
            c0814p = c0814p2;
            c0814p.X(-1824765311);
            if (m2Var != com.quizlet.data.model.m2.c) {
                if (m2Var == com.quizlet.data.model.m2.a) {
                    throw new kotlin.n(null, 1, null);
                }
                if (m2Var != com.quizlet.data.model.m2.b) {
                    throw new NoWhenBranchMatchedException();
                }
                throw new kotlin.n(null, 1, null);
            }
            mVar.u();
            d(c4458g, function1, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, (i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND);
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 20, m2Var, c4458g, function1);
        }
    }

    public static final void b(com.quizlet.data.model.m2 source, C4458g config, com.quizlet.assembly.compose.modals.x modalState, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(config, "config");
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1867778563);
        int i2 = i | (c0814p.f(source) ? 4 : 2) | (c0814p.f(config) ? 32 : 16) | (c0814p.h(modalState) ? 256 : 128) | (c0814p.h(function1) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            U5.b(modalState, null, false, null, null, null, androidx.compose.runtime.internal.e.e(-768212888, new com.quizlet.assembly.compose.menu.l(source, config, function1, 25), c0814p), c0814p, 1572872 | ((i2 >> 6) & 14), 62);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i(source, config, modalState, function1, i, 27);
        }
    }

    public static final void c(C0995g c0995g, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        C0995g c0995g2 = c0995g;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1089796665);
        int i2 = i | (c0814p.f(c0995g2) ? 4 : 2) | 48;
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.u();
            float f = com.quizlet.ui.resources.designsystem.generated.j.g;
            androidx.compose.ui.q qVarW = AbstractC0382e.w(nVar3, f, DefinitionKt.NO_Float_VALUE, 2);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarW);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            androidx.compose.material3.Q4.b("•", null, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).o, c0814p, 6, 0, 65534);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b)).o;
            mVar.u();
            c0995g2 = c0995g;
            androidx.compose.material3.Q4.c(c0995g2, AbstractC0382e.y(nVar3, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, null, l, c0814p, i2 & 14, 0, 131068);
            c0814p = c0814p;
            c0814p.p(true);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(c0995g2, nVar2, i, 12);
        }
    }

    public static final void d(C4458g c4458g, Function1 function1, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2130265078);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(c4458g) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function1) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.text.D d = new androidx.compose.ui.text.D(((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).e, 0L, (androidx.compose.ui.text.font.u) null, (androidx.compose.ui.text.font.q) null, (androidx.compose.ui.text.font.r) null, com.quizlet.ui.resources.designsystem.generated.a.e, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (androidx.compose.ui.text.style.o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (androidx.compose.ui.graphics.U) null, 65502);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(1575554429);
            C0984d c0984d = new C0984d();
            c0984d.f(AbstractC3106b5.d(c0814p, R.string.uuf_practice_test_guidelines_option_1));
            C0995g c0995gJ = c0984d.j();
            c0814p.p(false);
            c(c0995gJ, null, c0814p, 0);
            String strD = AbstractC3106b5.d(c0814p, R.string.uuf_practice_test_guidelines_academic_integrity_standards_highlighted);
            String strD2 = AbstractC3106b5.d(c0814p, R.string.uuf_practice_test_guidelines_community_guidelines_highlighted);
            String strD3 = AbstractC3106b5.d(c0814p, R.string.uuf_practice_test_guidelines_option_2);
            c0814p.X(1575572974);
            C0984d c0984d2 = new C0984d();
            c0984d2.f(strD3);
            c0984d2.c(d, StringsKt.M(strD3, strD, 0, false, 6), strD.length() + StringsKt.M(strD3, strD, 0, false, 6));
            c0984d2.c(d, StringsKt.M(strD3, strD2, 0, false, 6), strD2.length() + StringsKt.M(strD3, strD2, 0, false, 6));
            c0814p.X(-1660572652);
            int i4 = i2 & ContentType.LONG_FORM_ON_DEMAND;
            boolean z = i4 == 32;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                objI = new com.quizlet.features.infra.basestudy.ui.c(1, function1);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            c0984d2.a(new C1011l("academic_integrity_standards", null, (com.quizlet.features.infra.basestudy.ui.c) objI), StringsKt.M(strD3, strD, 0, false, 6), strD.length() + StringsKt.M(strD3, strD, 0, false, 6));
            c0814p.X(-1660556819);
            boolean z2 = i4 == 32;
            Object objI2 = c0814p.I();
            if (z2 || objI2 == v) {
                objI2 = new com.quizlet.features.infra.basestudy.ui.c(2, function1);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            c0984d2.a(new C1011l("community_guidelines", null, (com.quizlet.features.infra.basestudy.ui.c) objI2), StringsKt.M(strD3, strD2, 0, false, 6), strD2.length() + StringsKt.M(strD3, strD2, 0, false, 6));
            C0995g c0995gJ2 = c0984d2.j();
            c0814p.p(false);
            c(c0995gJ2, null, c0814p, 0);
            c0814p.X(1575621661);
            C0984d c0984d3 = new C0984d();
            c0984d3.f(AbstractC3106b5.d(c0814p, R.string.uuf_practice_test_guidelines_option_3));
            C0995g c0995gJ3 = c0984d3.j();
            c0814p.p(false);
            c(c0995gJ3, null, c0814p, 0);
            c0814p.X(1575627165);
            C0984d c0984d4 = new C0984d();
            c0984d4.f(AbstractC3106b5.d(c0814p, R.string.uuf_practice_test_guidelines_option_4));
            C0995g c0995gJ4 = c0984d4.j();
            c0814p.p(false);
            c(c0995gJ4, null, c0814p, 0);
            c0814p.X(1575632689);
            C0984d c0984d5 = new C0984d();
            c0984d5.f(AbstractC3106b5.c(R.string.uuf_practice_test_guidelines_option_5, new Object[]{25}, c0814p));
            C0995g c0995gJ5 = c0984d5.j();
            c0814p.p(false);
            c(c0995gJ5, null, c0814p, 0);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 12, qVar, (Object) c4458g, (Object) function1);
        }
    }

    public static Object e(Task task) {
        com.google.android.gms.common.internal.u.g("Must not be called on the main application thread");
        Looper looperMyLooper = Looper.myLooper();
        if (looperMyLooper != null && Objects.equals(looperMyLooper.getThread().getName(), "GoogleApiHandler")) {
            throw new IllegalStateException("Must not be called on GoogleApiHandler thread.");
        }
        com.google.android.gms.common.internal.u.i(task, "Task must not be null");
        if (task.k()) {
            return l(task);
        }
        com.quizlet.data.repository.school.membership.a aVar = new com.quizlet.data.repository.school.membership.a(21);
        Executor executor = com.google.android.gms.tasks.g.b;
        task.d(executor, aVar);
        task.c(executor, aVar);
        task.a(executor, aVar);
        ((CountDownLatch) aVar.b).await();
        return l(task);
    }

    public static Object f(Task task, long j, TimeUnit timeUnit) {
        com.google.android.gms.common.internal.u.g("Must not be called on the main application thread");
        Looper looperMyLooper = Looper.myLooper();
        if (looperMyLooper != null && Objects.equals(looperMyLooper.getThread().getName(), "GoogleApiHandler")) {
            throw new IllegalStateException("Must not be called on GoogleApiHandler thread.");
        }
        com.google.android.gms.common.internal.u.i(task, "Task must not be null");
        com.google.android.gms.common.internal.u.i(timeUnit, "TimeUnit must not be null");
        if (task.k()) {
            return l(task);
        }
        com.quizlet.data.repository.school.membership.a aVar = new com.quizlet.data.repository.school.membership.a(21);
        Executor executor = com.google.android.gms.tasks.g.b;
        task.d(executor, aVar);
        task.c(executor, aVar);
        task.a(executor, aVar);
        if (((CountDownLatch) aVar.b).await(j, timeUnit)) {
            return l(task);
        }
        throw new TimeoutException("Timed out waiting for Task");
    }

    public static com.google.android.gms.tasks.m g(Executor executor, Callable callable) {
        com.google.android.gms.common.internal.u.i(executor, "Executor must not be null");
        com.google.android.gms.tasks.m mVar = new com.google.android.gms.tasks.m();
        executor.execute(new com.google.android.gms.measurement.internal.A0(mVar, false, callable, 9));
        return mVar;
    }

    public static com.google.android.gms.tasks.m h(Exception exc) {
        com.google.android.gms.tasks.m mVar = new com.google.android.gms.tasks.m();
        mVar.r(exc);
        return mVar;
    }

    public static com.google.android.gms.tasks.m i(Object obj) {
        com.google.android.gms.tasks.m mVar = new com.google.android.gms.tasks.m();
        mVar.p(obj);
        return mVar;
    }

    public static com.google.android.gms.tasks.m j(List list) {
        if (list == null || list.isEmpty()) {
            return i(null);
        }
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            if (((Task) it2.next()) == null) {
                throw new NullPointerException("null tasks are not accepted");
            }
        }
        com.google.android.gms.tasks.m mVar = new com.google.android.gms.tasks.m();
        com.google.android.gms.tasks.h hVar = new com.google.android.gms.tasks.h(list.size(), mVar);
        Iterator it3 = list.iterator();
        while (it3.hasNext()) {
            Task task = (Task) it3.next();
            androidx.camera.core.impl.utils.executor.a aVar = com.google.android.gms.tasks.g.b;
            task.d(aVar, hVar);
            task.c(aVar, hVar);
            task.a(aVar, hVar);
        }
        return mVar;
    }

    public static Task k(Task... taskArr) {
        if (taskArr.length == 0) {
            return i(Collections.EMPTY_LIST);
        }
        List listAsList = Arrays.asList(taskArr);
        return (listAsList == null || listAsList.isEmpty()) ? i(Collections.EMPTY_LIST) : j(listAsList).f(com.google.android.gms.tasks.g.a, new com.google.android.gms.tasks.n(listAsList, 0));
    }

    public static Object l(Task task) throws ExecutionException {
        if (task.l()) {
            return task.h();
        }
        if (task.j()) {
            throw new CancellationException("Task is already canceled");
        }
        throw new ExecutionException(task.g());
    }
}
