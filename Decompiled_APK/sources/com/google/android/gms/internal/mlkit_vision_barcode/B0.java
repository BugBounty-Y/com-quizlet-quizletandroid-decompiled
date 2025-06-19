package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.vector.C0867f;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.navigation.compose.B;
import androidx.navigation.compose.x;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.assembly.compose.buttons.C4097w;
import com.quizlet.eventlogger.features.search.SearchType;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.InterfaceC4938g;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class B0 {
    public static C0867f a;

    public static final void a(int i, int i2, int i3, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        int i4;
        String strH;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1620511528);
        if ((i3 & 6) == 0) {
            i4 = (c0814p2.d(i) ? 4 : 2) | i3;
        } else {
            i4 = i3;
        }
        if ((i3 & 48) == 0) {
            i4 |= c0814p2.d(i2) ? 32 : 16;
        }
        if ((i3 & 384) == 0) {
            i4 |= c0814p2.h(function0) ? 256 : 128;
        }
        if ((i3 & 3072) == 0) {
            i4 |= c0814p2.f(qVar) ? 2048 : 1024;
        }
        if ((i4 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            if (i2 > 0) {
                strH = com.google.android.gms.measurement.internal.Z.h(c0814p2, 628897928, R.string.done, c0814p2, false);
            } else {
                c0814p2.X(628959246);
                c0814p2.X(-1111589514);
                int iMax = Math.max(i, 1);
                String quantityString = ((Context) c0814p2.j(AndroidCompositionLocals_androidKt.b)).getResources().getQuantityString(R.plurals.folder_items_count, iMax, Integer.valueOf(iMax));
                Intrinsics.checkNotNullExpressionValue(quantityString, "getQuantityString(...)");
                String str = AbstractC3106b5.d(c0814p2, R.string.new_tag_add) + " " + quantityString;
                c0814p2.p(false);
                c0814p2.p(false);
                strH = str;
            }
            c0814p = c0814p2;
            com.google.android.gms.internal.mlkit_vision_document_scanner.W4.a(strH, androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(qVar, 1.0f), "add_to_folder_done_button"), function0, false, null, C4097w.a, null, null, null, false, c0814p, i4 & 896, 984);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.addtofolder.composables.d(i, i2, function0, qVar, i3);
        }
    }

    public static final void b(androidx.compose.ui.q qVar, com.quizlet.features.folders.addtofolder.data.u uVar, Function1 function1, Function1 function12, Function0 function0, InterfaceC0806l interfaceC0806l, int i, int i2) {
        androidx.compose.ui.q qVar2;
        int i3;
        com.quizlet.features.folders.addtofolder.data.r rVarI;
        com.quizlet.features.folders.addtofolder.data.r rVarI2;
        androidx.compose.runtime.V v;
        int i4;
        int i5;
        boolean z;
        androidx.compose.ui.q qVar3;
        androidx.compose.ui.n nVar;
        androidx.compose.ui.q qVar4;
        androidx.compose.ui.q qVar5;
        boolean z2;
        String strH;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(119801123);
        int i6 = i2 & 1;
        if (i6 != 0) {
            i3 = i | 6;
            qVar2 = qVar;
        } else if ((i & 6) == 0) {
            qVar2 = qVar;
            i3 = (c0814p.f(qVar2) ? 4 : 2) | i;
        } else {
            qVar2 = qVar;
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p.h(uVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i3 |= c0814p.h(function1) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i3 |= c0814p.h(function12) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p.h(function0) ? 16384 : 8192;
        }
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            qVar4 = qVar2;
        } else {
            c0814p.S();
            int i7 = i & 1;
            androidx.compose.runtime.V v2 = C0804k.a;
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            if (i7 != 0 && !c0814p.w()) {
                c0814p.Q();
            } else if (i6 != 0) {
                qVar2 = nVar2;
            }
            androidx.compose.ui.q qVar6 = qVar2;
            c0814p.q();
            int i8 = i3 >> 3;
            c0814p.X(2126712347);
            c0814p.X(1943858262);
            boolean zIsEmpty = uVar.l.isEmpty();
            int i9 = uVar.k;
            List list = uVar.l;
            if (zIsEmpty) {
                rVarI2 = i(uVar, c0814p);
                c0814p.p(false);
                c0814p.p(false);
            } else {
                c0814p.p(false);
                com.quizlet.features.folders.addtofolder.data.t tVar = (com.quizlet.features.folders.addtofolder.data.t) list.get(i9);
                if (tVar == com.quizlet.features.folders.addtofolder.data.t.a) {
                    rVarI = uVar.g;
                } else {
                    if (tVar != com.quizlet.features.folders.addtofolder.data.t.b) {
                        throw new NoWhenBranchMatchedException();
                    }
                    rVarI = i(uVar, c0814p);
                }
                rVarI2 = rVarI;
                c0814p.p(false);
            }
            com.quizlet.features.folders.addtofolder.data.r rVar = rVarI2;
            Object[] objArr = new Object[0];
            c0814p.X(-1648659744);
            Object objI = c0814p.I();
            if (objI == v2) {
                objI = new com.quizlet.features.emailconfirmation.ui.composables.c(9);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            Object objD = L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i10 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar6);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i10))) {
                android.support.v4.media.session.a.z(i10, c0814p, i10, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(267341682);
            boolean z3 = true;
            if (list.isEmpty()) {
                v = v2;
                i4 = i9;
                i5 = 2048;
                z = false;
                qVar3 = qVar6;
                nVar = nVar2;
            } else {
                i4 = i9;
                objD = list.get(i4);
                c0814p.X(1775440676);
                ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    int iOrdinal = ((com.quizlet.features.folders.addtofolder.data.t) it2.next()).ordinal();
                    if (iOrdinal == 0) {
                        qVar5 = qVar6;
                        z2 = false;
                        strH = com.google.android.gms.measurement.internal.Z.h(c0814p, 554020624, R.string.others_are_studying, c0814p, false);
                    } else {
                        if (iOrdinal != z3) {
                            throw com.google.android.gms.measurement.internal.Z.j(554018879, c0814p, false);
                        }
                        qVar5 = qVar6;
                        z2 = false;
                        strH = com.google.android.gms.measurement.internal.Z.h(c0814p, 554023337, R.string.your_library, c0814p, false);
                    }
                    arrayList.add(new com.quizlet.features.infra.folder.a(strH, z2, true));
                    z3 = true;
                    qVar6 = qVar5;
                }
                qVar3 = qVar6;
                boolean z4 = z3;
                kotlinx.collections.immutable.b bVarI = AbstractC3409x1.i(arrayList);
                c0814p.p(false);
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.q();
                float f = com.quizlet.ui.resources.designsystem.generated.j.i;
                mVar.w();
                androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.f, 5);
                nVar = nVar2;
                c0814p.X(267357096);
                i5 = 2048;
                boolean zH = ((i3 & 7168) == 2048 ? z4 : false) | c0814p.h(uVar);
                Object objI2 = c0814p.I();
                if (zH) {
                    v = v2;
                } else {
                    v = v2;
                    if (objI2 == v) {
                    }
                    Function1 function13 = (Function1) objI2;
                    z = false;
                    c0814p.p(false);
                    E5.a(bVarI, uVar.k, qVarY, function13, false, c0814p, 0, 16);
                }
                objI2 = new androidx.lifecycle.u0(22, (Object) uVar, function12);
                c0814p.i0(objI2);
                Function1 function132 = (Function1) objI2;
                z = false;
                c0814p.p(false);
                E5.a(bVarI, uVar.k, qVarY, function132, false, c0814p, 0, 16);
            }
            c0814p.p(z);
            boolean z5 = (!uVar.h || CollectionsKt.O(i4, list) == com.quizlet.features.folders.addtofolder.data.t.b) ? true : z;
            boolean z6 = z;
            int i11 = i5;
            androidx.compose.runtime.V v3 = v;
            c(AbstractC3409x1.i(uVar.a), uVar.b, rVar, (com.quizlet.features.folders.addtofolder.data.t) objD, z5, androidx.compose.foundation.layout.C.a(nVar, 1.0f), uVar.j, function12, c0814p, (i3 << 12) & 29360128);
            c0814p = c0814p;
            c0814p.X(267383293);
            boolean z7 = (i3 & 896) == 256 ? true : z6;
            Object objI3 = c0814p.I();
            if (z7 || objI3 == v3) {
                objI3 = new androidx.navigation.compose.B(4, function1);
                c0814p.i0(objI3);
            }
            Function1 function14 = (Function1) objI3;
            c0814p.p(z6);
            c0814p.X(267386408);
            boolean z8 = (i3 & 7168) == i11 ? true : z6;
            Object objI4 = c0814p.I();
            if (z8 || objI4 == v3) {
                objI4 = new com.quizlet.facebook.a(4, function12);
                c0814p.i0(objI4);
            }
            c0814p.p(z6);
            d(uVar, function14, (Function0) objI4, function0, null, c0814p, i8 & 7182);
            c0814p.p(true);
            qVar4 = qVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.h(qVar4, uVar, function1, function12, function0, i, i2, 2);
        }
    }

    public static final void c(final kotlinx.collections.immutable.b bVar, com.quizlet.features.folders.addtofolder.data.o oVar, final com.quizlet.features.folders.addtofolder.data.r rVar, com.quizlet.features.folders.addtofolder.data.t tVar, boolean z, androidx.compose.ui.q qVar, String str, final Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.features.folders.addtofolder.data.o oVar2;
        com.quizlet.features.folders.addtofolder.data.t tVar2;
        boolean z2;
        String str2;
        boolean z3;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1115498530);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(bVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            oVar2 = oVar;
            i2 |= c0814p2.f(oVar2) ? 32 : 16;
        } else {
            oVar2 = oVar;
        }
        if ((i & 384) == 0) {
            i2 |= (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0 ? c0814p2.f(rVar) : c0814p2.h(rVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            tVar2 = tVar;
            i2 |= c0814p2.f(tVar2) ? 2048 : 1024;
        } else {
            tVar2 = tVar;
        }
        if ((i & 24576) == 0) {
            z2 = z;
            i2 |= c0814p2.g(z2) ? 16384 : 8192;
        } else {
            z2 = z;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p2.f(qVar) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            str2 = str;
            i2 |= c0814p2.f(str2) ? 1048576 : 524288;
        } else {
            str2 = str;
        }
        if ((i & 12582912) == 0) {
            i2 |= c0814p2.h(function1) ? 8388608 : 4194304;
        }
        if ((i2 & 4793491) == 4793490 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            final androidx.compose.foundation.lazy.A a2 = androidx.compose.foundation.lazy.D.a(0, c0814p2, 3);
            androidx.compose.ui.q qVarD = M5.d(androidx.compose.foundation.layout.K0.c(qVar, 1.0f), a2);
            com.quizlet.themes.m.g.q();
            androidx.compose.foundation.layout.A0 a0C = AbstractC0382e.c(DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, 1);
            c0814p2.X(1476616907);
            boolean zF = ((i2 & 14) == 4) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((57344 & i2) == 16384) | ((29360128 & i2) == 8388608) | ((i2 & 896) == 256 || ((i2 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 && c0814p2.h(rVar))) | ((3670016 & i2) == 1048576) | c0814p2.f(a2) | ((i2 & 7168) == 2048);
            Object objI = c0814p2.I();
            if (zF || objI == C0804k.a) {
                final com.quizlet.features.folders.addtofolder.data.o oVar3 = oVar2;
                final com.quizlet.features.folders.addtofolder.data.t tVar3 = tVar2;
                final boolean z4 = z2;
                final String str3 = str2;
                z3 = false;
                Function1 function12 = new Function1() { // from class: com.quizlet.features.folders.addtofolder.composables.b
                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) {
                        int i3;
                        androidx.compose.foundation.lazy.g LazyColumn = (androidx.compose.foundation.lazy.g) obj;
                        Intrinsics.checkNotNullParameter(LazyColumn, "$this$LazyColumn");
                        kotlinx.collections.immutable.b bVar2 = bVar;
                        com.quizlet.features.folders.addtofolder.data.o oVar4 = oVar3;
                        boolean z5 = z4;
                        Function1 function13 = function1;
                        androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, -1754108395, new f(bVar2, oVar4, z5, function13)), 3);
                        com.quizlet.features.folders.addtofolder.data.q qVar2 = com.quizlet.features.folders.addtofolder.data.q.a;
                        com.quizlet.features.folders.addtofolder.data.r rVar2 = rVar;
                        if (Intrinsics.b(rVar2, qVar2)) {
                            LazyColumn.q(4, null, androidx.compose.foundation.lazy.o.c, u.a);
                        } else {
                            if (!(rVar2 instanceof com.quizlet.features.folders.addtofolder.data.p)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.quizlet.features.folders.addtofolder.data.p pVar = (com.quizlet.features.folders.addtofolder.data.p) rVar2;
                            pVar.getClass();
                            ArrayList arrayList = new ArrayList();
                            for (Object obj2 : pVar.a) {
                                com.quizlet.ui.models.content.listitem.o oVar5 = ((com.quizlet.features.folders.addtofolder.data.s) obj2).a;
                                String str4 = str3;
                                if (str4 == null) {
                                    str4 = "";
                                }
                                if (oVar5.c(str4)) {
                                    arrayList.add(obj2);
                                }
                            }
                            kotlinx.collections.immutable.b bVarI = AbstractC3409x1.i(arrayList);
                            if (bVarI.isEmpty()) {
                                int iOrdinal = tVar3.ordinal();
                                if (iOrdinal == 0) {
                                    i3 = R.string.add_to_folder_recommendations_empty_content_message;
                                } else {
                                    if (iOrdinal != 1) {
                                        throw new NoWhenBranchMatchedException();
                                    }
                                    i3 = R.string.add_to_folder_empty_content_message;
                                }
                                androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, 1901682382, new e(i3, 0)), 3);
                            } else {
                                kotlinx.collections.immutable.b bVarI2 = AbstractC3409x1.i(bVarI);
                                com.quizlet.explanations.questiondetail.ui.composables.l lVar = new com.quizlet.explanations.questiondetail.ui.composables.l(1, function13);
                                B b = new B(3, function13);
                                LazyColumn.q(bVarI2.size(), new androidx.compose.ui.viewinterop.b(11, new x(6), bVarI2), new g(bVarI2, 0), new androidx.compose.runtime.internal.d(true, -1091073711, new com.quizlet.assembly.compose.menu.f(bVarI2, b, a2, lVar, 1)));
                            }
                        }
                        return Unit.a;
                    }
                };
                c0814p2.i0(function12);
                objI = function12;
            } else {
                z3 = false;
            }
            c0814p2.p(z3);
            c0814p = c0814p2;
            AbstractC3137f0.a(qVarD, a2, a0C, null, null, null, false, (Function1) objI, c0814p, 0, 248);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.addtofolder.composables.c(bVar, oVar, rVar, tVar, z, qVar, str, function1, i);
        }
    }

    public static final void d(com.quizlet.features.folders.addtofolder.data.u uVar, Function1 function1, Function0 function0, Function0 function02, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function1 function12;
        Function0 function03;
        Function0 function04;
        androidx.compose.ui.n nVar2;
        androidx.compose.ui.n nVar3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-196837726);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(uVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            function12 = function1;
            i2 |= c0814p.h(function12) ? 32 : 16;
        } else {
            function12 = function1;
        }
        if ((i & 384) == 0) {
            function03 = function0;
            i2 |= c0814p.h(function03) ? 256 : 128;
        } else {
            function03 = function0;
        }
        if ((i & 3072) == 0) {
            function04 = function02;
            i2 |= c0814p.h(function04) ? 2048 : 1024;
        } else {
            function04 = function02;
        }
        int i3 = i2 | 24576;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            nVar3 = nVar;
        } else {
            androidx.compose.ui.n nVar4 = androidx.compose.ui.n.b;
            if (uVar.m + uVar.n == 0) {
                c0814p.X(-6102098);
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.s();
                float f = com.quizlet.ui.resources.designsystem.generated.j.h;
                mVar.s();
                mVar.p();
                nVar2 = nVar4;
                e(AbstractC3409x1.i(uVar.c), function12, AbstractC0382e.y(nVar4, f, DefinitionKt.NO_Float_VALUE, f, com.quizlet.ui.resources.designsystem.generated.j.j, 2), function03, c0814p, (i3 & ContentType.LONG_FORM_ON_DEMAND) | ((i3 << 3) & 7168));
                c0814p = c0814p;
                c0814p.p(false);
            } else {
                c0814p.X(-5637067);
                com.quizlet.themes.m mVar2 = com.quizlet.themes.m.g;
                mVar2.s();
                float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
                mVar2.s();
                mVar2.p();
                nVar2 = nVar4;
                a(uVar.m, uVar.n, (i3 >> 3) & 896, c0814p, AbstractC0382e.y(nVar4, f2, DefinitionKt.NO_Float_VALUE, f2, com.quizlet.ui.resources.designsystem.generated.j.j, 2), function04);
                c0814p.p(false);
            }
            nVar3 = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p((Object) uVar, function1, (Object) function0, (InterfaceC4938g) function02, (Object) nVar3, i, 1);
        }
    }

    public static final void e(kotlinx.collections.immutable.b bVar, Function1 function1, androidx.compose.ui.q qVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function1 function12;
        androidx.compose.ui.q qVar2;
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(649527108);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(bVar) : c0814p.h(bVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            function12 = function1;
            i2 |= c0814p.h(function12) ? 32 : 16;
        } else {
            function12 = function1;
        }
        if ((i & 384) == 0) {
            qVar2 = qVar;
            i2 |= c0814p.f(qVar2) ? 256 : 128;
        } else {
            qVar2 = qVar;
        }
        if ((i & 3072) == 0) {
            function02 = function0;
            i2 |= c0814p.h(function02) ? 2048 : 1024;
        } else {
            function02 = function0;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.quizlet.assembly.compose.menu.s sVarB = com.google.android.gms.internal.mlkit_vision_document_scanner.K5.b(c0814p);
            c0814p.X(-1190354103);
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(bVar, 10));
            Iterator<E> it2 = bVar.iterator();
            while (it2.hasNext()) {
                com.quizlet.features.folders.menu.c cVar = (com.quizlet.features.folders.menu.c) it2.next();
                arrayList.add(new com.quizlet.assembly.compose.menu.o(cVar, cVar.a(c0814p), cVar.b(c0814p), null, false, null, false, 248));
            }
            c0814p.p(false);
            com.google.android.gms.internal.mlkit_vision_document_scanner.M5.a(androidx.compose.runtime.internal.e.e(1854334205, new com.quizlet.assembly.compose.buttons.A(qVar2, function02, sVarB, arrayList, 4), c0814p), null, sVarB, function12, null, null, c0814p, ((i2 << 6) & 7168) | 6, 50);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i(bVar, function1, qVar, function0, i);
        }
    }

    public static final void f(String query, SearchType searchType, androidx.compose.ui.n nVar, float f, com.quizlet.search.viewmodels.G g, Function2 function2, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        boolean z;
        androidx.compose.foundation.lazy.grid.A a2;
        int i2;
        C0814p c0814p;
        androidx.compose.ui.n nVar3;
        Intrinsics.checkNotNullParameter(query, "query");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1453135040);
        int i3 = i | (c0814p2.f(query) ? 4 : 2) | (c0814p2.f(searchType) ? 32 : 16) | 384 | (c0814p2.c(f) ? 2048 : 1024) | (c0814p2.h(g) ? 16384 : 8192) | (c0814p2.h(function2) ? 131072 : 65536);
        if ((74899 & i3) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            nVar3 = nVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            int i4 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i4 == 0 || c0814p2.w()) {
                nVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p2.Q();
                nVar2 = nVar;
            }
            c0814p2.q();
            androidx.compose.foundation.lazy.grid.A a3 = androidx.compose.foundation.lazy.grid.B.a(0, c0814p2, 3);
            int iD = AbstractC3236q0.d(c0814p2);
            androidx.compose.ui.q qVarG = androidx.compose.foundation.layout.K0.c(nVar2, 1.0f).g(androidx.compose.foundation.layout.K0.b);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.foundation.layout.A0 a0C = Q5.c(new androidx.compose.foundation.layout.A0(f2, f2, f2, f2), f);
            C0380d c0380d = AbstractC0398m.a;
            mVar.s();
            C0392j c0392jG = AbstractC0398m.g(f2);
            mVar.s();
            C0392j c0392jG2 = AbstractC0398m.g(f2);
            c0814p2.X(-85366740);
            boolean zH = ((i3 & 14) == 4) | c0814p2.h(g);
            Object objI = c0814p2.I();
            if (zH || objI == v) {
                z = false;
                objI = new com.quizlet.search.composables.K(g, query, 0);
                c0814p2.i0(objI);
            } else {
                z = false;
            }
            Function0 function0 = (Function0) objI;
            c0814p2.p(z);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(1991906821, new com.quizlet.search.composables.q(f, 3), c0814p2);
            c0814p2.X(-85345665);
            boolean zD = ((458752 & i3) == 131072) | c0814p2.d(iD) | ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32) | c0814p2.f(a3) | c0814p2.h(g);
            Object objI2 = c0814p2.I();
            if (zD || objI2 == v) {
                a2 = a3;
                objI2 = new com.quizlet.quizletandroid.ui.globalnav.composable.d(iD, function2, searchType, a2, g, 13);
                i2 = iD;
                c0814p2.i0(objI2);
            } else {
                i2 = iD;
                a2 = a3;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC3266t5.b(function0, qVarG, 0L, i2, a0C, c0392jG, c0392jG2, a2, dVarE, null, (Function2) objI2, c0814p, 100663296, 516);
            nVar3 = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.search.composables.p(query, searchType, nVar3, f, g, function2, i, 3);
        }
    }

    public static final String g(boolean z, C0814p c0814p) {
        int i;
        int i2;
        c0814p.X(639501632);
        if (z) {
            i = -561824024;
            i2 = R.string.remove_from_folder_action_a11y;
        } else {
            i = -561750771;
            i2 = R.string.add_to_folder_action_a11y;
        }
        String strH = com.google.android.gms.measurement.internal.Z.h(c0814p, i, i2, c0814p, false);
        c0814p.p(false);
        return strH;
    }

    public static final int h(boolean z) {
        return z ? R.drawable.ic_sys_circled_check_filled : R.drawable.ic_sys_plus_circled;
    }

    public static final com.quizlet.features.folders.addtofolder.data.r i(com.quizlet.features.folders.addtofolder.data.u uVar, InterfaceC0806l interfaceC0806l) {
        com.quizlet.features.folders.addtofolder.data.r rVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(950978190);
        int iOrdinal = uVar.b.ordinal();
        if (iOrdinal == 0) {
            rVar = uVar.d;
        } else if (iOrdinal == 1) {
            rVar = uVar.e;
        } else {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            rVar = uVar.f;
        }
        c0814p.p(false);
        return rVar;
    }

    public static final String j(com.quizlet.features.folders.addtofolder.data.s sVar) {
        int iB = sVar.a.b().b();
        com.quizlet.ui.models.content.listitem.o oVar = sVar.a;
        return "item:" + iB + ":" + oVar.d() + ":" + oVar.a() + ":" + sVar.b;
    }
}
