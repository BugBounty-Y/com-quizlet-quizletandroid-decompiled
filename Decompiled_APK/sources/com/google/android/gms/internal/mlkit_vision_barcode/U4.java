package com.google.android.gms.internal.mlkit_vision_barcode;

import android.graphics.Canvas;
import android.graphics.Paint;
import androidx.compose.ui.graphics.AbstractC0845e;
import androidx.compose.ui.graphics.C0850j;
import androidx.compose.ui.graphics.InterfaceC0858s;
import com.quizlet.data.model.AbstractC4119d0;
import com.quizlet.data.model.ContentFolder;
import com.quizlet.shared.models.api.base.QuizletApiThreeResponse;
import com.quizlet.shared.models.api.base.QuizletApiWrapper;
import com.quizlet.shared.models.api.base.errors.QuizletApiError;
import com.quizlet.shared.models.api.exceptions.QuizletApiException;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class U4 {
    public static final void a(androidx.compose.ui.graphics.drawscope.d dVar, androidx.compose.ui.graphics.layer.b bVar) {
        boolean z;
        float f;
        InterfaceC0858s interfaceC0858sO = dVar.e0().o();
        androidx.compose.ui.graphics.layer.b bVar2 = (androidx.compose.ui.graphics.layer.b) dVar.e0().c;
        if (bVar.r) {
            return;
        }
        bVar.a();
        androidx.compose.ui.graphics.layer.d dVar2 = bVar.a;
        if (!dVar2.h()) {
            try {
                bVar.e();
            } catch (Throwable unused) {
            }
        }
        boolean z2 = dVar2.J() > DefinitionKt.NO_Float_VALUE;
        if (z2) {
            interfaceC0858sO.t();
        }
        Canvas canvasA = AbstractC0845e.a(interfaceC0858sO);
        boolean zIsHardwareAccelerated = canvasA.isHardwareAccelerated();
        if (!zIsHardwareAccelerated) {
            canvasA.save();
            long j = bVar.s;
            float f2 = (int) (j >> 32);
            float f3 = (int) (j & 4294967295L);
            long j2 = bVar.t;
            float f4 = ((int) (j2 >> 32)) + f2;
            float f5 = ((int) (j2 & 4294967295L)) + f3;
            float fA = dVar2.a();
            int iL = dVar2.L();
            if (fA < 1.0f || iL != 3 || dVar2.s() == 1) {
                com.google.android.gms.cloudmessaging.k kVarG = bVar.o;
                if (kVarG == null) {
                    kVarG = androidx.compose.ui.graphics.F.g();
                    bVar.o = kVarG;
                }
                kVarG.d(fA);
                kVarG.e(iL);
                kVarG.g(null);
                canvasA = canvasA;
                f = f2;
                canvasA.saveLayer(f, f3, f4, f5, (Paint) kVarG.c);
            } else {
                canvasA.save();
                canvasA = canvasA;
                f = f2;
            }
            canvasA.translate(f, f3);
            canvasA.concat(dVar2.I());
        }
        boolean z3 = !zIsHardwareAccelerated && bVar.v;
        if (z3) {
            interfaceC0858sO.e();
            androidx.compose.ui.graphics.N nC = bVar.c();
            if (nC instanceof androidx.compose.ui.graphics.L) {
                InterfaceC0858s.k(interfaceC0858sO, nC.a());
            } else if (nC instanceof androidx.compose.ui.graphics.M) {
                C0850j c0850jH = bVar.m;
                if (c0850jH != null) {
                    c0850jH.a.rewind();
                } else {
                    c0850jH = androidx.compose.ui.graphics.F.h();
                    bVar.m = c0850jH;
                }
                androidx.compose.ui.graphics.O.b(c0850jH, ((androidx.compose.ui.graphics.M) nC).a);
                interfaceC0858sO.i(c0850jH);
            } else if (nC instanceof androidx.compose.ui.graphics.K) {
                interfaceC0858sO.i(((androidx.compose.ui.graphics.K) nC).a);
            }
        }
        if (bVar2 != null) {
            androidx.compose.material.ripple.r rVar = bVar2.q;
            if (!rVar.a) {
                throw new IllegalArgumentException("Only add dependencies during a tracking");
            }
            androidx.collection.J j3 = (androidx.collection.J) rVar.d;
            if (j3 != null) {
                j3.a(bVar);
            } else if (((androidx.compose.ui.graphics.layer.b) rVar.b) != null) {
                int i = androidx.collection.U.a;
                androidx.collection.J j4 = new androidx.collection.J();
                androidx.compose.ui.graphics.layer.b bVar3 = (androidx.compose.ui.graphics.layer.b) rVar.b;
                Intrinsics.d(bVar3);
                j4.a(bVar3);
                j4.a(bVar);
                rVar.d = j4;
                rVar.b = null;
            } else {
                rVar.b = bVar;
            }
            androidx.collection.J j5 = (androidx.collection.J) rVar.e;
            if (j5 != null) {
                z = !j5.j(bVar);
            } else if (((androidx.compose.ui.graphics.layer.b) rVar.c) != bVar) {
                z = true;
            } else {
                rVar.c = null;
                z = false;
            }
            if (z) {
                bVar.p++;
            }
        }
        dVar2.M(interfaceC0858sO);
        if (z3) {
            interfaceC0858sO.q();
        }
        if (z2) {
            interfaceC0858sO.f();
        }
        if (zIsHardwareAccelerated) {
            return;
        }
        canvasA.restore();
    }

    public static final kotlin.q b(QuizletApiError quizletApiError, R4 r4) {
        kotlin.p pVar = kotlin.r.b;
        return androidx.glance.appwidget.protobuf.Z.b(new QuizletApiException(quizletApiError, r4.c()));
    }

    public static final String c(AbstractC4119d0 abstractC4119d0, boolean z) {
        Intrinsics.checkNotNullParameter(abstractC4119d0, "<this>");
        return abstractC4119d0 instanceof ContentFolder ? ((ContentFolder) abstractC4119d0).s : ((abstractC4119d0 instanceof com.quizlet.data.model.J) && z) ? ((com.quizlet.data.model.J) abstractC4119d0).m() : "";
    }

    public static final Object d(QuizletApiWrapper quizletApiWrapper, R4 request, Function1 getDataFromResponse) {
        List list;
        QuizletApiThreeResponse quizletApiThreeResponse;
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(getDataFromResponse, "getDataFromResponse");
        if (quizletApiWrapper == null || (list = quizletApiWrapper.a) == null || (quizletApiThreeResponse = (QuizletApiThreeResponse) CollectionsKt.firstOrNull(list)) == null) {
            return b(quizletApiWrapper != null ? quizletApiWrapper.b : null, request);
        }
        Intrinsics.checkNotNullParameter(quizletApiThreeResponse, "<this>");
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(getDataFromResponse, "getDataFromResponse");
        Object objInvoke = getDataFromResponse.invoke(quizletApiThreeResponse);
        if (objInvoke == null) {
            return b(quizletApiThreeResponse.c, request);
        }
        kotlin.p pVar = kotlin.r.b;
        return objInvoke;
    }
}
