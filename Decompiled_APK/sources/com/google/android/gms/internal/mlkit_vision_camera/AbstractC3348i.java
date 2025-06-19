package com.google.android.gms.internal.mlkit_vision_camera;

import android.content.Context;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.M7;
import com.google.android.gms.internal.mlkit_vision_barcode.z7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.flashcards.C4236j;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.i, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3348i {
    /* JADX WARN: Removed duplicated region for block: B:100:0x02d2  */
    /* JADX WARN: Removed duplicated region for block: B:104:0x0347  */
    /* JADX WARN: Removed duplicated region for block: B:105:0x034b  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x0358  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x0366  */
    /* JADX WARN: Removed duplicated region for block: B:113:0x03e7  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x03e9  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x03f5  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x03fa  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x0420  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x0499  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x019d  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x019f  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x01a8  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0222  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x0226  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x0241  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x02bc  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x02c0  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x02cd  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(com.quizlet.data.model.m2 r43, kotlin.jvm.functions.Function0 r44, kotlin.jvm.functions.Function0 r45, final kotlin.jvm.functions.Function1 r46, androidx.compose.ui.q r47, androidx.compose.foundation.layout.z0 r48, androidx.compose.runtime.InterfaceC0806l r49, int r50) {
        /*
            Method dump skipped, instructions count: 1361
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.AbstractC3348i.a(com.quizlet.data.model.m2, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function1, androidx.compose.ui.q, androidx.compose.foundation.layout.z0, androidx.compose.runtime.l, int):void");
    }

    public static final void b(com.quizlet.features.notes.upload.states.h hVar, Function0 function0, kotlin.jvm.functions.d dVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        boolean z;
        Function1 function12 = function1;
        int i3 = 16;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-386378127);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(hVar) : c0814p.h(hVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(dVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function12) ? 2048 : 1024;
        }
        int i4 = i2;
        if ((i4 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(true, false, c0814p, 6, 6);
            c0814p.X(1129061103);
            Object objI = c0814p.I();
            if (objI == v) {
                objI = C0776c.z(Boolean.FALSE);
                c0814p.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
            c0814p.p(false);
            c0814p.X(1129063156);
            boolean z2 = (i4 & 14) == 4 || ((i4 & 8) != 0 && c0814p.h(hVar));
            int i5 = i4 & ContentType.LONG_FORM_ON_DEMAND;
            boolean z3 = z2 | (i5 == 32);
            Object objI2 = c0814p.I();
            if (z3 || objI2 == v) {
                objI2 = new androidx.work.impl.utils.q(hVar, function0, interfaceC0773a0, i3);
                c0814p.i0(objI2);
            }
            Function0 function02 = (Function0) objI2;
            c0814p.p(false);
            c0814p.X(1129069887);
            boolean zF = c0814p.f(function02);
            Object objI3 = c0814p.I();
            if (zF || objI3 == v) {
                objI3 = new com.braze.support.u(20, function02);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            androidx.work.impl.t.a(false, (Function0) objI3, c0814p, 0, 1);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(AbstractC0460p.f(androidx.compose.ui.n.b, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), androidx.compose.ui.graphics.F.a), "UploadNotesScreen");
            c0814p.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p).g, new C0416v0(C0380d.e(c0814p).k, AbstractC0382e.g));
            c0814p.p(false);
            function12 = function1;
            AbstractC0725t3.a(qVarG, androidx.compose.runtime.internal.e.e(-1876393419, new com.quizlet.assembly.compose.buttons.A(hVar, function02, function12, xVarH, 13), c0814p), androidx.compose.runtime.internal.e.e(-1627115018, new androidx.navigation.compose.o(25, hVar, function12), c0814p), null, null, 0, 0L, 0L, c0374a, androidx.compose.runtime.internal.e.e(487810112, new com.quizlet.assembly.compose.input.h(hVar, function12, dVar, 9), c0814p), c0814p, 805306800, 248);
            c0814p = c0814p;
            c0814p.X(1129155217);
            if (hVar instanceof com.quizlet.features.notes.upload.states.a) {
                boolean z4 = ((com.quizlet.features.notes.upload.states.a) hVar).d;
                c0814p.X(1129161617);
                boolean z5 = (i4 & 7168) == 2048;
                Object objI4 = c0814p.I();
                if (z5 || objI4 == v) {
                    objI4 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.l(6, function12);
                    c0814p.i0(objI4);
                }
                z = false;
                c0814p.p(false);
                z7.c(z4, xVarH, (Function1) objI4, c0814p, 64);
            } else {
                z = false;
            }
            c0814p.p(z);
            if ((hVar instanceof com.quizlet.features.notes.upload.states.f) && ((Boolean) interfaceC0773a0.getValue()).booleanValue()) {
                com.quizlet.data.model.m2 m2Var = ((com.quizlet.features.notes.upload.states.f) hVar).a;
                c0814p.X(1129174610);
                Object objI5 = c0814p.I();
                if (objI5 == v) {
                    objI5 = new androidx.navigation.compose.z(interfaceC0773a0, 26);
                    c0814p.i0(objI5);
                }
                c0814p.p(z);
                M7.b(i5 | 384, c0814p, m2Var, function0, (Function0) objI5);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i(hVar, function0, dVar, function12, i, 18);
        }
    }

    public static final void c(int i, InterfaceC0806l interfaceC0806l, Function0 function0, Function0 function02, boolean z) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-925468863);
        int i2 = (c0814p.h(function0) ? 4 : 2) | i | (c0814p.h(function02) ? 32 : 16) | (c0814p.g(z) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.quizlet.themes.e.a(c0814p).a.getClass();
            AbstractC3691o6.c(null, null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), 0L, com.quizlet.ui.resources.icons.d.m(c0814p), function0, androidx.compose.runtime.internal.e.e(-1374844001, new com.quizlet.features.flashcards.views.c(z, function02, 2), c0814p), null, c0814p, ((i2 << 15) & 458752) | 1572864, 139);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.upload.composables.upload.e(function0, function02, z, i);
        }
    }

    public static final void d(Function0 navigateBack, Function0 navigateToUpgrade, Function2 navigateToSetPage, Function0 navigateToPaywall, Function1 navigateToCreateSet, kotlin.jvm.functions.c navigateToMagicNotesDetail, kotlin.jvm.functions.d navigateToPasteText, com.quizlet.features.notes.upload.viewmodels.k kVar, InterfaceC0806l interfaceC0806l, int i) {
        boolean z;
        int i2;
        com.quizlet.features.notes.upload.viewmodels.k kVar2;
        kotlinx.coroutines.flow.Y y;
        com.quizlet.features.notes.upload.viewmodels.k kVar3;
        com.quizlet.features.notes.upload.viewmodels.k kVar4;
        Intrinsics.checkNotNullParameter(navigateBack, "navigateBack");
        Intrinsics.checkNotNullParameter(navigateToUpgrade, "navigateToUpgrade");
        Intrinsics.checkNotNullParameter(navigateToSetPage, "navigateToSetPage");
        Intrinsics.checkNotNullParameter(navigateToPaywall, "navigateToPaywall");
        Intrinsics.checkNotNullParameter(navigateToCreateSet, "navigateToCreateSet");
        Intrinsics.checkNotNullParameter(navigateToMagicNotesDetail, "navigateToMagicNotesDetail");
        Intrinsics.checkNotNullParameter(navigateToPasteText, "navigateToPasteText");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1338590093);
        int i3 = i | (c0814p.h(navigateToUpgrade) ? 32 : 16) | (c0814p.h(navigateToPaywall) ? 2048 : 1024) | (c0814p.h(navigateToPasteText) ? 1048576 : 524288) | 4194304;
        if ((4793491 & i3) == 4793490 && c0814p.x()) {
            c0814p.Q();
            kVar4 = kVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                z = false;
                androidx.lifecycle.w0 w0VarE = AbstractC3417z1.e(com.quizlet.features.notes.upload.viewmodels.k.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                i2 = i3 & (-29360129);
                kVar2 = (com.quizlet.features.notes.upload.viewmodels.k) w0VarE;
            } else {
                c0814p.Q();
                i2 = i3 & (-29360129);
                kVar2 = kVar;
                z = false;
            }
            int i4 = i2;
            c0814p.q();
            Context context = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
            c0814p.X(-1719363756);
            boolean zH = c0814p.h(kVar2);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (zH || objI == v) {
                objI = new com.quizlet.features.folders.composables.J(kVar2, 6);
                c0814p.i0(objI);
            }
            Function1 function1 = (Function1) objI;
            c0814p.p(z);
            Intrinsics.checkNotNullParameter(context, "context");
            c0814p.X(-1420069422);
            c0814p.X(1343791034);
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = new com.quizlet.features.infra.document.b();
                c0814p.i0(objI2);
            }
            com.quizlet.features.infra.document.b bVar = (com.quizlet.features.infra.document.b) objI2;
            c0814p.p(z);
            androidx.activity.result.contract.b bVar2 = new androidx.activity.result.contract.b(5);
            c0814p.X(1343801231);
            boolean zF = c0814p.f(function1);
            Object objI3 = c0814p.I();
            if (zF || objI3 == v) {
                objI3 = new androidx.navigation.compose.B(22, function1);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            androidx.activity.compose.o oVarF = androidx.work.P.f(bVar2, (Function1) objI3, c0814p);
            c0814p.X(1343809487);
            boolean zF2 = c0814p.f(bVar) | c0814p.h(context) | c0814p.h(oVarF);
            Object objI4 = c0814p.I();
            if (zF2 || objI4 == v) {
                objI4 = new androidx.work.impl.utils.q(bVar, context, oVarF, 13);
                c0814p.i0(objI4);
            }
            Function0 function0 = (Function0) objI4;
            c0814p.p(false);
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(new kotlinx.coroutines.flow.Z(kVar2.E()), c0814p);
            kotlinx.coroutines.flow.Y y2 = new kotlinx.coroutines.flow.Y(kVar2.k);
            c0814p.X(-1719356987);
            boolean zF3 = ((i4 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i4 & 7168) == 2048) | c0814p.f(function0) | ((3670016 & i4) == 1048576);
            Object objI5 = c0814p.I();
            if (zF3 || objI5 == v) {
                y = y2;
                com.quizlet.features.notes.upload.composables.upload.h hVar = new com.quizlet.features.notes.upload.composables.upload.h(navigateBack, navigateToCreateSet, navigateToUpgrade, navigateToPaywall, function0, navigateToPasteText, navigateToMagicNotesDetail, navigateToSetPage, null);
                c0814p.i0(hVar);
                objI5 = hVar;
            } else {
                y = y2;
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI5, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF4 = c0814p.f(b) | c0814p.h(j) | c0814p.h(y) | c0814p.f(interfaceC0773a0D);
            Object objI6 = c0814p.I();
            if (zF4 || objI6 == v) {
                objI6 = new com.quizlet.features.notes.upload.composables.upload.g(interfaceC0773a0D, j, null, y);
                c0814p.i0(objI6);
            }
            c0814p.p(false);
            com.quizlet.features.notes.upload.states.h hVar2 = (com.quizlet.features.notes.upload.states.h) AbstractC4178x.k(unit, (Function2) objI6, c0814p, false, interfaceC0773a0M);
            c0814p.X(-1719323259);
            boolean zH2 = c0814p.h(kVar2);
            Object objI7 = c0814p.I();
            if (zH2 || objI7 == v) {
                com.quizlet.features.notes.upload.viewmodels.k kVar5 = kVar2;
                objI7 = new com.quizlet.features.notes.detail.composables.magicnotesdetail.G(1, kVar5, com.quizlet.features.notes.upload.viewmodels.k.class, "onEventReceived", "onEventReceived(Lcom/quizlet/features/notes/common/events/MagicNotesEvent;)V", 0, 7);
                kVar3 = kVar5;
                c0814p.i0(objI7);
            } else {
                kVar3 = kVar2;
            }
            c0814p.p(false);
            b(hVar2, navigateBack, navigateToPasteText, (Function1) ((kotlin.reflect.f) objI7), c0814p, 48 | ((i4 >> 12) & 896));
            c0814p.X(-1719318284);
            boolean zH3 = c0814p.h(kVar3);
            Object objI8 = c0814p.I();
            if (zH3 || objI8 == v) {
                objI8 = new com.quizlet.features.notes.upload.composables.upload.i(kVar3, null);
                c0814p.i0(objI8);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI8);
            kVar4 = kVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4236j(navigateBack, navigateToUpgrade, navigateToSetPage, navigateToPaywall, navigateToCreateSet, navigateToMagicNotesDetail, navigateToPasteText, kVar4, i);
        }
    }

    public static final String e(Number from, Number until) {
        Intrinsics.checkNotNullParameter(from, "from");
        Intrinsics.checkNotNullParameter(until, "until");
        return "Random range is empty: [" + from + ", " + until + ").";
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:26:0x007d A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0086 A[Catch: all -> 0x0031, TryCatch #1 {all -> 0x0031, blocks: (B:12:0x002d, B:27:0x007e, B:29:0x0086, B:30:0x0091, B:39:0x00a4, B:24:0x006d, B:41:0x00a7, B:42:0x00ab, B:43:0x00ac, B:23:0x0067, B:31:0x0092, B:33:0x0098), top: B:59:0x0021, outer: #4, inners: #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00ad A[Catch: all -> 0x00bc, TRY_ENTER, TRY_LEAVE, TryCatch #4 {all -> 0x00bc, blocks: (B:44:0x00ad, B:49:0x00b8, B:50:0x00bb, B:12:0x002d, B:27:0x007e, B:29:0x0086, B:30:0x0091, B:39:0x00a4, B:24:0x006d, B:41:0x00a7, B:42:0x00ab, B:43:0x00ac, B:23:0x0067, B:31:0x0092, B:33:0x0098, B:47:0x00b6), top: B:59:0x0021, inners: #1, #3 }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r6v4, types: [kotlinx.coroutines.channels.w] */
    /* JADX WARN: Type inference failed for: r8v0, types: [java.lang.Object, java.util.Collection] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:25:0x007b -> B:27:0x007e). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object f(kotlin.coroutines.jvm.internal.c r10) {
        /*
            Method dump skipped, instructions count: 196
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.AbstractC3348i.f(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final int g(kotlin.random.d dVar, IntRange range) {
        Intrinsics.checkNotNullParameter(dVar, "<this>");
        Intrinsics.checkNotNullParameter(range, "range");
        if (range.isEmpty()) {
            throw new IllegalArgumentException("Cannot get random in empty range: " + range);
        }
        int i = range.a;
        int i2 = range.b;
        if (i2 < Integer.MAX_VALUE) {
            dVar.getClass();
            return kotlin.random.e.b.e(i, i2 + 1);
        }
        if (i <= Integer.MIN_VALUE) {
            dVar.getClass();
            return kotlin.random.e.b.c();
        }
        dVar.getClass();
        return kotlin.random.e.b.e(i - 1, i2) + 1;
    }
}
