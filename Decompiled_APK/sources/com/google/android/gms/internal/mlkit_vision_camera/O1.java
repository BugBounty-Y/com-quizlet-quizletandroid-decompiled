package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.navigation.compose.C1280m;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Z5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.internal.AbstractC5044b;
import kotlinx.serialization.internal.AbstractC5047c0;

/* loaded from: classes2.dex */
public abstract class O1 {
    public static final void a(com.quizlet.data.model.R0 image, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(image, "image");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1775251985);
        if ((((c0814p.h(image) ? 4 : 2) | i | 48) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            qVar2 = androidx.compose.ui.n.b;
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(false, false, c0814p, 0, 7);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            androidx.compose.ui.q qVarK = androidx.compose.foundation.layout.K0.k(qVar2, com.quizlet.themes.m.R0);
            mVar.s();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarK, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            c0814p.X(-1477514733);
            boolean zH = c0814p.h(xVarH);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new com.quizlet.features.folders.changetags.composables.f(xVarH, 9);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            r3.b(image.a, image.b, AbstractC0460p.l(qVarY, false, null, (Function0) objI, 7), Z4.a(R.drawable.ic_sys_image_gray400, c0814p, 0), null, c0814p, 0, 32752);
            Z5.c(image.a, null, xVarH, c0814p, com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(image, qVar2, i, 24);
        }
    }

    public static final KSerializer b(AbstractC5044b abstractC5044b, kotlinx.serialization.encoding.a decoder, String str) {
        Intrinsics.checkNotNullParameter(abstractC5044b, "<this>");
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        KSerializer kSerializerA = abstractC5044b.a(decoder, str);
        if (kSerializerA != null) {
            return kSerializerA;
        }
        AbstractC5047c0.l(str, abstractC5044b.c());
        throw null;
    }

    public static final KSerializer c(AbstractC5044b abstractC5044b, Encoder encoder, Object value) {
        Intrinsics.checkNotNullParameter(abstractC5044b, "<this>");
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        KSerializer kSerializerB = abstractC5044b.b(encoder, value);
        if (kSerializerB != null) {
            return kSerializerB;
        }
        C4950i subClass = kotlin.jvm.internal.K.a(value.getClass());
        kotlin.reflect.c baseClass = abstractC5044b.c();
        Intrinsics.checkNotNullParameter(subClass, "subClass");
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        String strF = subClass.f();
        if (strF == null) {
            strF = String.valueOf(subClass);
        }
        AbstractC5047c0.l(strF, baseClass);
        throw null;
    }

    /* JADX WARN: Removed duplicated region for block: B:6:0x0032  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.navigation.H d(androidx.navigation.W[] r8, androidx.compose.runtime.InterfaceC0806l r9) {
        /*
            r0 = 0
            androidx.compose.runtime.X0 r1 = androidx.compose.ui.platform.AndroidCompositionLocals_androidKt.b
            r5 = r9
            androidx.compose.runtime.p r5 = (androidx.compose.runtime.C0814p) r5
            java.lang.Object r9 = r5.j(r1)
            android.content.Context r9 = (android.content.Context) r9
            int r1 = r8.length
            java.lang.Object[] r2 = java.util.Arrays.copyOf(r8, r1)
            androidx.navigation.compose.x r1 = new androidx.navigation.compose.x
            r1.<init>(r0)
            androidx.navigation.compose.y r3 = new androidx.navigation.compose.y
            r3.<init>(r9, r0)
            com.quizlet.data.repository.explanations.myexplanations.a r4 = androidx.compose.runtime.saveable.m.a
            r4 = r3
            com.quizlet.data.repository.explanations.myexplanations.a r3 = new com.quizlet.data.repository.explanations.myexplanations.a
            r6 = 3
            r3.<init>(r1, r0, r4, r6)
            boolean r1 = r5.h(r9)
            java.lang.Object r4 = r5.I()
            if (r1 != 0) goto L32
            androidx.compose.runtime.V r1 = androidx.compose.runtime.C0804k.a
            if (r4 != r1) goto L3a
        L32:
            androidx.navigation.compose.w r4 = new androidx.navigation.compose.w
            r4.<init>(r9, r0)
            r5.i0(r4)
        L3a:
            kotlin.jvm.functions.Function0 r4 = (kotlin.jvm.functions.Function0) r4
            r7 = 4
            r6 = 0
            java.lang.Object r9 = com.google.android.gms.internal.mlkit_vision_barcode.L4.d(r2, r3, r4, r5, r6, r7)
            androidx.navigation.H r9 = (androidx.navigation.H) r9
            int r1 = r8.length
        L45:
            if (r0 >= r1) goto L53
            r2 = r8[r0]
            androidx.navigation.internal.j r3 = r9.b
            androidx.navigation.X r3 = r3.s
            r3.a(r2)
            int r0 = r0 + 1
            goto L45
        L53:
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.O1.d(androidx.navigation.W[], androidx.compose.runtime.l):androidx.navigation.H");
    }
}
