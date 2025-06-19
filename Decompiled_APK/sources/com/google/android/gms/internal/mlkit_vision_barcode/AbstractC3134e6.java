package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import android.view.View;
import android.widget.TextView;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.foundation.layout.LayoutWeightElement;
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
import com.comscore.streaming.AdvertisementType;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3769y5;
import com.quizlet.assembly.compose.modals.C4103b;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.e6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3134e6 {
    public static final void a(com.quizlet.assembly.compose.modals.x modalState, com.quizlet.features.infra.folder.menu.screenstates.d state, androidx.compose.ui.q qVar, Function1 function1, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        Intrinsics.checkNotNullParameter(state, "state");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1329238222);
        int i2 = i | (c0814p.h(modalState) ? 4 : 2) | (c0814p.f(state) ? 32 : 16) | 384 | (c0814p.h(function1) ? 2048 : 1024) | (c0814p.h(function0) ? 16384 : 8192) | (c0814p.h(function02) ? 131072 : 65536);
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            c0814p.X(986915164);
            Object objI = c0814p.I();
            if (objI == v) {
                objI = new C4103b(function0, modalState, 5);
                c0814p.i0(objI);
            }
            Function0 function03 = (Function0) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(986920424, c0814p, false);
            if (objG == v) {
                objG = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.y(function1, modalState, 1);
                c0814p.i0(objG);
            }
            Function1 function12 = (Function1) objG;
            c0814p.p(false);
            com.google.android.gms.internal.mlkit_vision_document_scanner.U5.a(modalState, androidx.compose.runtime.internal.e.e(-495569768, new com.quizlet.features.infra.folder.menu.composable.h(state, function03, function12, function02, 0), c0814p), androidx.compose.ui.platform.N.G(nVar, "AddToFolderMenu"), androidx.compose.runtime.internal.e.e(-1363497130, new com.quizlet.features.infra.folder.menu.composable.h(state, function03, function12, function02, 1), c0814p), null, null, null, false, function02, c0814p, (i2 & 14) | 3128 | ((i2 << 9) & 234881024), 240);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.e((Object) modalState, (Object) state, (Object) qVar2, (Object) function1, function0, function02, i, 2);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void b(com.quizlet.features.infra.folder.menu.screenstates.d dVar, boolean z, androidx.compose.ui.q qVar, Function0 function0, Function1 function1, Function0 function02, InterfaceC0806l interfaceC0806l, int i, int i2) {
        androidx.compose.ui.q qVar2;
        int i3;
        ArrayList arrayList;
        float f;
        Function1 function12;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1711749245);
        int i4 = i | (c0814p2.f(dVar) ? 4 : 2);
        int i5 = i2 & 4;
        if (i5 != 0) {
            i3 = i4 | 384;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i3 = i4 | (c0814p2.f(qVar2) ? 256 : 128);
        }
        int i6 = i3 | (c0814p2.h(function02) ? 131072 : 65536);
        if ((74899 & i6) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            function12 = function1;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVar3 = i5 != 0 ? nVar : qVar2;
            Object obj = C0804k.a;
            c0814p2.X(1123900582);
            int i7 = i6 & 14;
            boolean z2 = i7 == 4;
            Object objI = c0814p2.I();
            Object obj2 = objI;
            if (z2 || objI == obj) {
                if (dVar instanceof com.quizlet.features.infra.folder.menu.screenstates.c) {
                    kotlinx.collections.immutable.e eVar = ((com.quizlet.features.infra.folder.menu.screenstates.c) dVar).a;
                    arrayList = new ArrayList();
                    for (Object obj3 : eVar) {
                        if (obj3 instanceof com.quizlet.features.infra.folder.menu.data.b) {
                            arrayList.add(obj3);
                        }
                    }
                } else {
                    arrayList = kotlin.collections.K.a;
                }
                c0814p2.i0(arrayList);
                obj2 = arrayList;
            }
            Object obj4 = (List) obj2;
            c0814p2.p(false);
            int i8 = i6 >> 6;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p2, 0);
            int i9 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVar3);
            InterfaceC0915k.D0.getClass();
            Function0 function03 = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(function03);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, bA, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i9))) {
                android.support.v4.media.session.a.z(i9, c0814p2, i9, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.s();
            if (z) {
                mVar.r();
                f = com.quizlet.ui.resources.designsystem.generated.j.e;
            } else {
                mVar.s();
                f = f2;
            }
            d(z, AbstractC0382e.y(nVar, f2, f, f2, DefinitionKt.NO_Float_VALUE, 8), function0, function02, c0814p2, (i8 & 7168) | 390);
            mVar.s();
            mVar.h();
            float f3 = com.quizlet.ui.resources.designsystem.generated.h.g;
            androidx.compose.foundation.layout.A0 a0 = new androidx.compose.foundation.layout.A0(f2, f3, f2, f3);
            mVar.n();
            C0392j c0392jG = AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.o);
            c0814p2.X(-1369559797);
            boolean zH = (i7 == 4) | c0814p2.h(obj4);
            Object objI2 = c0814p2.I();
            if (zH || objI2 == obj) {
                function12 = function1;
                objI2 = new androidx.lifecycle.compose.d(dVar, obj4, function12, 10);
                c0814p2.i0(objI2);
            } else {
                function12 = function1;
            }
            c0814p2.p(false);
            C0814p c0814p3 = c0814p2;
            AbstractC3137f0.a(null, null, a0, c0392jG, null, null, false, (Function1) objI2, c0814p3, 0, AdvertisementType.BRANDED_DURING_LIVE);
            c0814p3.p(true);
            qVar2 = qVar3;
            c0814p = c0814p3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.diagrams.ui.f(dVar, z, qVar2, function0, function12, function02, i, i2);
        }
    }

    public static final void c(Function0 function0, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        Function0 function02;
        androidx.compose.runtime.internal.d dVar2;
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1199277128);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(nVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(dVar) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            function02 = function0;
            c0814p = c0814p2;
            dVar2 = dVar;
        } else {
            com.quizlet.themes.m.g.c();
            androidx.compose.foundation.shape.d dVarA = androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.h);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            c0814p = c0814p2;
            function02 = function0;
            dVar2 = dVar;
            androidx.compose.material3.Z1.d(function02, nVar, false, dVarA, androidx.compose.material3.Z1.o(((com.quizlet.themes.b) c0814p2.j(b)).f, ((com.quizlet.themes.b) c0814p2.j(b)).b.e(), 0L, c0814p2, 0, 12), null, null, null, dVar2, c0814p, ((i2 >> 3) & 14) | ((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND) | ((i2 << 18) & 234881024), 228);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(function02, dVar2, i);
        }
    }

    public static final void d(boolean z, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.text.L l;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1792530805);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function0) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function02) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            if (z) {
                c0814p.X(807210776);
                l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).e;
                c0814p.p(false);
            } else {
                c0814p.X(807265429);
                l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).i;
                c0814p.p(false);
            }
            androidx.compose.ui.text.L l2 = l;
            c0814p.X(857328542);
            androidx.compose.runtime.internal.d dVarE = z ? null : androidx.compose.runtime.internal.e.e(-341024178, new com.quizlet.explanations.questiondetail.ui.composables.m(8, function02), c0814p);
            c0814p.p(false);
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.u();
            float f = com.quizlet.ui.resources.designsystem.generated.j.g;
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarC, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14);
            C0380d c0380d = AbstractC0398m.a;
            mVar.m();
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.n), androidx.compose.ui.b.k, c0814p, 48);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarY);
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
            C0776c.E(c0814p, qVarC2, C0914j.d);
            c0814p.X(585186080);
            if (dVarE != null) {
                dVarE.invoke(c0814p, 0);
            }
            c0814p.p(false);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.save), new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true), 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l2, c0814p, 0, 0, 65532);
            c0814p = c0814p;
            String strD = AbstractC3106b5.d(c0814p, R.string.create_new_folder);
            mVar.u();
            AbstractC3769y5.a(strD, null, null, new androidx.compose.foundation.layout.A0(f, f, f, f), null, function0, c0814p, (i2 << 9) & 458752, 22);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.recyclerview.step.g(z, qVar, function0, function02, i);
        }
    }

    public static final void e(com.quizlet.features.infra.folder.menu.data.b bVar, androidx.compose.ui.n nVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-515739034);
        int i2 = (c0814p.h(bVar) ? 4 : 2) | i | 48 | (c0814p.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            nVar = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            c0814p.X(142943249);
            boolean zH = ((i2 & 896) == 256) | c0814p.h(bVar);
            Object objI = c0814p.I();
            if (zH || objI == v) {
                objI = new com.quizlet.features.infra.folder.menu.composable.g(function1, bVar, 0);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            c((Function0) objI, androidx.compose.runtime.internal.e.e(-1592125, new com.quizlet.baseui.base.d(bVar, 3), c0814p), c0814p, 390);
        }
        androidx.compose.ui.n nVar2 = nVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 27, bVar, nVar2, function1);
        }
    }

    public static String f() {
        StackTraceElement stackTraceElement = new Throwable().getStackTrace()[1];
        return ".(" + stackTraceElement.getFileName() + ":" + stackTraceElement.getLineNumber() + ")";
    }

    public static String g(Context context, int i) {
        if (i == -1) {
            return "UNKNOWN";
        }
        try {
            return context.getResources().getResourceEntryName(i);
        } catch (Exception unused) {
            return android.support.v4.media.session.a.f(i, "?");
        }
    }

    public static String h(View view) {
        try {
            return view.getContext().getResources().getResourceEntryName(view.getId());
        } catch (Exception unused) {
            return "UNKNOWN";
        }
    }

    public static final void i(TextView textView, String str) {
        Intrinsics.checkNotNullParameter(textView, "<this>");
        textView.setText(str);
        textView.setVisibility((str == null || str.length() == 0) ? 8 : 0);
    }
}
