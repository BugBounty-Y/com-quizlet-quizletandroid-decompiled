package com.google.android.gms.internal.mlkit_vision_camera;

import android.text.Editable;
import android.text.Layout;
import android.text.style.BackgroundColorSpan;
import android.text.style.ForegroundColorSpan;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3586b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.T5;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ListIterator;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class T2 {
    public static final void a(com.quizlet.assembly.compose.modals.x popupState, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.assembly.compose.modals.x xVar;
        Intrinsics.checkNotNullParameter(popupState, "popupState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-488063121);
        int i2 = (c0814p.h(popupState) ? 4 : 2) | i | 48;
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            xVar = popupState;
        } else {
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            xVar = popupState;
            T5.a(nVar2, xVar, false, null, null, androidx.compose.runtime.internal.e.e(988624228, new com.quizlet.features.questiontypes.fitb.ui.f(popupState, 0), c0814p), c0814p, 196678 | ((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND), 28);
            nVar = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.detail.composables.d(xVar, nVar, i, 1);
        }
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.n nVar, Function0 function0) {
        androidx.compose.ui.n nVar2;
        Function0 function02 = function0;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1684044278);
        int i2 = i | 6 | (c0814p.h(function02) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            androidx.compose.ui.q qVarU = AbstractC0382e.u(qVarC, com.quizlet.ui.resources.designsystem.generated.j.i);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarU);
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
            C0776c.E(c0814p, qVarC2, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p, R.string.fill_in_the_blank_modal_title);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jE = ((com.quizlet.themes.b) c0814p.j(b)).b.e();
            androidx.compose.runtime.B b2 = com.quizlet.themes.w.a;
            Q4.b(strD, null, jE, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b2)).e, c0814p, 0, 0, 65530);
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar3, f));
            Q4.b(AbstractC3106b5.d(c0814p, R.string.fill_in_the_blank_modal_message), null, ((com.quizlet.themes.b) c0814p.j(b)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b2)).o, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            mVar.s();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar3, f));
            nVar2 = nVar3;
            function02 = function0;
            AbstractC3586b5.a(AbstractC3106b5.d(c0814p, R.string.got_it_button), androidx.compose.foundation.layout.K0.c(nVar3, 1.0f), function02, false, null, null, null, null, null, c0814p, ((i2 << 3) & 896) | 48, 1016);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.A(nVar2, function02, i, 1);
        }
    }

    public static void c(org.wordpress.aztec.spans.C attributedSpan, Editable text, int i, int i2) {
        Intrinsics.checkNotNullParameter(text, "output");
        if (attributedSpan.f().a("style")) {
            Intrinsics.checkNotNullParameter(text, "text");
            Intrinsics.checkNotNullParameter(attributedSpan, "attributedSpan");
            if (!attributedSpan.f().a("style") || i == i2) {
                return;
            }
            String strD = H2.d("color", attributedSpan.f());
            if (!StringsKt.O(strD)) {
                Object obj = org.wordpress.aztec.util.c.a;
                int iC = org.wordpress.aztec.util.b.c(strD);
                if (iC != -1) {
                    text.setSpan(new ForegroundColorSpan(iC), i, i2, 33);
                }
            }
            String strD2 = H2.d("background-color", attributedSpan.f());
            if (!StringsKt.O(strD2)) {
                Object obj2 = org.wordpress.aztec.util.c.a;
                int iC2 = org.wordpress.aztec.util.b.c(strD2);
                if (iC2 != -1) {
                    text.setSpan(new BackgroundColorSpan(iC2), i, i2, 33);
                }
            }
            if (attributedSpan instanceof org.wordpress.aztec.spans.L) {
                org.wordpress.aztec.spans.L l = (org.wordpress.aztec.spans.L) attributedSpan;
                if (l instanceof org.wordpress.aztec.spans.B) {
                    String strD3 = H2.d("text-align", l.f());
                    if (StringsKt.O(strD3)) {
                        return;
                    }
                    boolean zT = androidx.core.text.f.c.t(text, i, i2 - i);
                    ((org.wordpress.aztec.spans.B) l).c(strD3.equals("right") ? zT ? Layout.Alignment.ALIGN_NORMAL : Layout.Alignment.ALIGN_OPPOSITE : strD3.equals("center") ? Layout.Alignment.ALIGN_CENTER : !zT ? Layout.Alignment.ALIGN_NORMAL : Layout.Alignment.ALIGN_OPPOSITE);
                }
            }
        }
    }

    public static final void d(LinkedHashMap newQuestions, List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        Intrinsics.checkNotNullParameter(newQuestions, "newQuestions");
        ListIterator listIterator = list.listIterator();
        while (listIterator.hasNext()) {
            assistantMode.refactored.types.d dVar = (assistantMode.refactored.types.d) newQuestions.get(((assistantMode.refactored.types.d) listIterator.next()).getMetadata().a);
            if (dVar != null) {
                listIterator.set(dVar);
            }
        }
    }

    public static final void e(ArrayList sortedIds, List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        Intrinsics.checkNotNullParameter(sortedIds, "sortedIds");
        if (list.size() > 1) {
            kotlin.collections.F.t(list, new androidx.camera.core.streamsharing.a(sortedIds, 5));
        }
    }

    public static final ArrayList f(Collection collection) {
        Intrinsics.checkNotNullParameter(collection, "<this>");
        Collection collection2 = collection;
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(collection2, 10));
        Iterator it2 = collection2.iterator();
        while (it2.hasNext()) {
            Long l = ((assistantMode.refactored.types.d) it2.next()).getMetadata().a;
            Intrinsics.d(l);
            arrayList.add(l);
        }
        return arrayList;
    }
}
