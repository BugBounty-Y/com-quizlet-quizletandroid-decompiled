package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class I4 {
    public static final /* synthetic */ int a = 0;

    public static final void a(com.quizlet.features.folders.menu.m menuSate, Function0 onShowMoreClick, Function1 onFolderOptionsMenuClicked, Function0 onMenuDismissed, InterfaceC0806l interfaceC0806l, int i) {
        String strH;
        androidx.compose.ui.graphics.painter.b bVarL;
        Intrinsics.checkNotNullParameter(menuSate, "menuSate");
        Intrinsics.checkNotNullParameter(onShowMoreClick, "onShowMoreClick");
        Intrinsics.checkNotNullParameter(onFolderOptionsMenuClicked, "onFolderOptionsMenuClicked");
        Intrinsics.checkNotNullParameter(onMenuDismissed, "onMenuDismissed");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1842312696);
        int i2 = i | (c0814p.f(menuSate) ? 4 : 2) | (c0814p.h(onShowMoreClick) ? 32 : 16) | (c0814p.h(onFolderOptionsMenuClicked) ? 256 : 128) | (c0814p.h(onMenuDismissed) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.quizlet.assembly.compose.menu.s sVarB = com.google.android.gms.internal.mlkit_vision_document_scanner.K5.b(c0814p);
            c0814p.X(-103468368);
            if ((menuSate instanceof com.quizlet.features.folders.menu.j) || Intrinsics.b(menuSate, com.quizlet.features.folders.menu.k.a)) {
                sVarB.a();
            } else {
                if (!(menuSate instanceof com.quizlet.features.folders.menu.l)) {
                    throw new NoWhenBranchMatchedException();
                }
                ArrayList arrayList = ((com.quizlet.features.folders.menu.l) menuSate).a;
                c0814p.X(-1917965689);
                ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    com.quizlet.features.folders.menu.i iVar = (com.quizlet.features.folders.menu.i) it2.next();
                    c0814p.X(-700951306);
                    boolean z = iVar instanceof com.quizlet.features.folders.menu.f;
                    com.quizlet.features.folders.menu.d dVar = com.quizlet.features.folders.menu.d.a;
                    com.quizlet.features.folders.menu.g gVar = com.quizlet.features.folders.menu.g.a;
                    if (z) {
                        strH = com.google.android.gms.measurement.internal.Z.h(c0814p, 1383740918, R.string.delete_folder, c0814p, false);
                    } else if (Intrinsics.b(iVar, gVar)) {
                        strH = com.google.android.gms.measurement.internal.Z.h(c0814p, 1383743476, R.string.edit_folder, c0814p, false);
                    } else if (iVar instanceof com.quizlet.features.folders.menu.h) {
                        strH = com.google.android.gms.measurement.internal.Z.h(c0814p, 1383746119, R.string.share, c0814p, false);
                    } else if (Intrinsics.b(iVar, dVar)) {
                        strH = com.google.android.gms.measurement.internal.Z.h(c0814p, 1383749442, R.string.add_study_materials_title, c0814p, false);
                    } else {
                        if (!(iVar instanceof com.quizlet.features.folders.menu.e)) {
                            throw com.google.android.gms.measurement.internal.Z.j(1383739566, c0814p, false);
                        }
                        strH = com.google.android.gms.measurement.internal.Z.h(c0814p, 1383752336, R.string.add_tag, c0814p, false);
                    }
                    c0814p.p(false);
                    c0814p.X(-441004691);
                    if (z) {
                        c0814p.X(-704995431);
                        com.quizlet.themes.e.a(c0814p).a.getClass();
                        bVarL = com.quizlet.ui.resources.icons.d.z(c0814p);
                        c0814p.p(false);
                    } else if (Intrinsics.b(iVar, gVar)) {
                        c0814p.X(-704993386);
                        com.quizlet.themes.e.a(c0814p).a.getClass();
                        bVarL = com.quizlet.ui.resources.icons.d.v(c0814p);
                        c0814p.p(false);
                    } else if (iVar instanceof com.quizlet.features.folders.menu.h) {
                        c0814p.X(-704991305);
                        com.quizlet.themes.e.a(c0814p).a.getClass();
                        bVarL = com.quizlet.ui.resources.icons.d.K(c0814p);
                        c0814p.p(false);
                    } else if (Intrinsics.b(iVar, dVar)) {
                        c0814p.X(-704989091);
                        com.quizlet.themes.e.a(c0814p).a.getClass();
                        bVarL = com.quizlet.ui.resources.icons.d.G(c0814p);
                        c0814p.p(false);
                    } else {
                        if (!(iVar instanceof com.quizlet.features.folders.menu.e)) {
                            throw com.google.android.gms.measurement.internal.Z.j(-704997493, c0814p, false);
                        }
                        c0814p.X(-704986955);
                        com.quizlet.themes.e.a(c0814p).a.getClass();
                        bVarL = com.quizlet.ui.resources.icons.d.L(c0814p);
                        c0814p.p(false);
                    }
                    c0814p.p(false);
                    arrayList2.add(new com.quizlet.assembly.compose.menu.o(iVar, strH, bVarL, null, iVar.isEnabled(), null, Intrinsics.b(iVar, com.quizlet.features.folders.menu.f.a), 88));
                }
                c0814p.p(false);
                com.google.android.gms.internal.mlkit_vision_document_scanner.J5.a(sVarB, arrayList2);
            }
            c0814p.p(false);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = -com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.r();
            com.google.android.gms.internal.mlkit_vision_document_scanner.M5.a(androidx.compose.runtime.internal.e.e(-288653183, new com.quizlet.explanations.questiondetail.ui.composables.m(5, onShowMoreClick), c0814p), null, sVarB, onFolderOptionsMenuClicked, new com.quizlet.assembly.compose.menu.r(new com.quizlet.assembly.compose.menu.t(N5.b(f, com.quizlet.ui.resources.designsystem.generated.j.e))), onMenuDismissed, c0814p, ((i2 << 3) & 7168) | 6 | ((i2 << 6) & 458752), 2);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i((Object) menuSate, onShowMoreClick, onFolderOptionsMenuClicked, onMenuDismissed, i, 5);
        }
    }

    public static final void b(int i, int i2) {
        if (i < 0 || i >= i2) {
            throw new IndexOutOfBoundsException(androidx.compose.animation.d0.p("index: ", i, ", size: ", i2));
        }
    }

    public static final void c(int i, int i2) {
        if (i < 0 || i > i2) {
            throw new IndexOutOfBoundsException(androidx.compose.animation.d0.p("index: ", i, ", size: ", i2));
        }
    }

    public static final void d(int i, int i2, int i3) {
        if (i < 0 || i2 > i3) {
            StringBuilder sbW = android.support.v4.media.session.a.w("fromIndex: ", i, ", toIndex: ", ", size: ", i2);
            sbW.append(i3);
            throw new IndexOutOfBoundsException(sbW.toString());
        }
        if (i > i2) {
            throw new IllegalArgumentException(androidx.compose.animation.d0.p("fromIndex: ", i, " > toIndex: ", i2));
        }
    }
}
