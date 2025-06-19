package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.BroadcastReceiver;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.r7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3251r7 {
    public static final void a(com.quizlet.features.notes.detail.menu.n menuState, Function0 onShowMoreClicked, Function1 onMenuItemClicked, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(menuState, "menuState");
        Intrinsics.checkNotNullParameter(onShowMoreClicked, "onShowMoreClicked");
        Intrinsics.checkNotNullParameter(onMenuItemClicked, "onMenuItemClicked");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-184664126);
        int i2 = i | (c0814p.f(menuState) ? 4 : 2) | (c0814p.h(onShowMoreClicked) ? 32 : 16) | (c0814p.h(onMenuItemClicked) ? 256 : 128) | (c0814p.h(function0) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.quizlet.assembly.compose.menu.s sVarB = com.google.android.gms.internal.mlkit_vision_document_scanner.K5.b(c0814p);
            c0814p.X(1237172331);
            if (menuState instanceof com.quizlet.features.notes.detail.menu.l) {
                sVarB.a();
            } else {
                if (!(menuState instanceof com.quizlet.features.notes.detail.menu.m)) {
                    throw new NoWhenBranchMatchedException();
                }
                ArrayList arrayList = ((com.quizlet.features.notes.detail.menu.m) menuState).a;
                c0814p.X(1506229178);
                ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    com.quizlet.features.notes.detail.menu.f fVar = (com.quizlet.features.notes.detail.menu.f) it2.next();
                    arrayList2.add(new com.quizlet.assembly.compose.menu.o(fVar, fVar.a(c0814p), fVar.b(c0814p), null, false, null, fVar.c(), 120));
                }
                c0814p.p(false);
                com.google.android.gms.internal.mlkit_vision_document_scanner.J5.a(sVarB, arrayList2);
            }
            c0814p.p(false);
            com.google.android.gms.internal.mlkit_vision_document_scanner.M5.a(androidx.compose.runtime.internal.e.e(-1882302469, new com.quizlet.explanations.questiondetail.ui.composables.m(11, onShowMoreClicked), c0814p), null, sVarB, onMenuItemClicked, com.onetrust.otpublishers.headless.Internal.Helper.h.x(), function0, c0814p, ((i2 << 3) & 7168) | 6 | ((i2 << 6) & 458752), 2);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i((Object) menuState, onShowMoreClicked, onMenuItemClicked, function0, i, 17);
        }
    }

    public static final void b(BroadcastReceiver broadcastReceiver, AbstractC5040y abstractC5040y, Function2 function2) {
        kotlinx.coroutines.internal.d dVarC = kotlinx.coroutines.E.c(kotlin.coroutines.k.c(abstractC5040y, kotlinx.coroutines.E.e()));
        kotlinx.coroutines.E.A(dVarC, null, null, new androidx.glance.appwidget.B(function2, dVarC, broadcastReceiver.goAsync(), null), 3);
    }

    public static Object c(io.ktor.utils.io.t tVar, androidx.navigation.internal.e eVar, io.ktor.client.engine.okhttp.g gVar) throws Throwable {
        io.ktor.utils.io.k kVar = (io.ktor.utils.io.k) tVar;
        kotlinx.io.a aVarI = kVar.i();
        kotlinx.io.g gVarI = aVarI.i(1);
        int i = gVarI.c;
        byte[] data = gVarI.a;
        ByteBuffer byteBufferWrap = ByteBuffer.wrap(data, i, data.length - i);
        Intrinsics.d(byteBufferWrap);
        eVar.invoke(byteBufferWrap);
        int iPosition = byteBufferWrap.position() - i;
        if (iPosition == 1) {
            Intrinsics.checkNotNullParameter(data, "data");
            gVarI.c += iPosition;
            aVarI.c += iPosition;
        } else {
            if (iPosition < 0 || iPosition > gVarI.a()) {
                StringBuilder sbV = android.support.v4.media.session.a.v(iPosition, "Invalid number of bytes written: ", ". Should be in 0..");
                sbV.append(gVarI.a());
                throw new IllegalStateException(sbV.toString().toString());
            }
            if (iPosition != 0) {
                Intrinsics.checkNotNullParameter(data, "data");
                gVarI.c += iPosition;
                aVarI.c += iPosition;
            } else if (kotlinx.io.j.c(gVarI)) {
                aVarI.d();
            }
        }
        Object objG = kVar.g(gVar);
        return objG == kotlin.coroutines.intrinsics.a.a ? objG : Unit.a;
    }
}
