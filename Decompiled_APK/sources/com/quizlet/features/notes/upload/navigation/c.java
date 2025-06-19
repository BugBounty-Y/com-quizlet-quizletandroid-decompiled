package com.quizlet.features.notes.upload.navigation;

import android.content.Context;
import android.text.SpannableStringBuilder;
import android.text.style.StyleSpan;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.lifecycle.u0;
import androidx.navigation.H;
import androidx.navigation.W;
import androidx.navigation.compose.C1280m;
import androidx.navigation.serialization.j;
import androidx.work.impl.utils.q;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.measurement.AbstractC3088z1;
import com.google.android.gms.internal.mlkit_vision_camera.O1;
import com.google.android.gms.internal.mlkit_vision_camera.Q1;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.m2;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.qutils.string.h;
import com.quizlet.qutils.string.i;
import kotlin.collections.A;
import kotlin.collections.K;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public abstract class c {
    public static final /* synthetic */ int a = 0;

    public static final void a(com.quizlet.features.notes.manager.a navigationManager, m2 source, String str, kotlinx.collections.immutable.b bVar, AddMaterialFolderData addMaterialFolderData, H h, InterfaceC0806l interfaceC0806l, int i) {
        H hD;
        int i2;
        H h2;
        C0814p c0814p;
        H h3;
        Intrinsics.checkNotNullParameter(navigationManager, "navigationManager");
        Intrinsics.checkNotNullParameter(source, "source");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(804314268);
        int i3 = i | (c0814p2.f(navigationManager) ? 4 : 2) | (c0814p2.f(source) ? 32 : 16) | (c0814p2.f(str) ? 256 : 128) | (c0814p2.h(bVar) ? 2048 : 1024) | (c0814p2.h(addMaterialFolderData) ? 16384 : 8192) | 65536;
        if ((74899 & i3) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            h3 = h;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                hD = O1.d(new W[0], c0814p2);
                i2 = i3 & (-458753);
            } else {
                c0814p2.Q();
                i2 = i3 & (-458753);
                hD = h;
            }
            c0814p2.q();
            Context context = (Context) c0814p2.j(AndroidCompositionLocals_androidKt.b);
            c0814p2.X(2138120487);
            Object objI = c0814p2.I();
            V v = C0804k.a;
            if (objI == v) {
                objI = new q(addMaterialFolderData, navigationManager, context, 18);
                c0814p2.i0(objI);
            }
            Function0 function0 = (Function0) objI;
            Object objG = Z.g(2138129726, c0814p2, false);
            if (objG == v) {
                objG = new j(3, navigationManager, function0);
                c0814p2.i0(objG);
            }
            kotlin.jvm.functions.c cVar = (kotlin.jvm.functions.c) objG;
            Object objG2 = Z.g(2138138801, c0814p2, false);
            if (objG2 == v) {
                objG2 = new u0(24, navigationManager, function0);
                c0814p2.i0(objG2);
            }
            Function1 function1 = (Function1) objG2;
            Object objG3 = Z.g(2138144697, c0814p2, false);
            if (objG3 == v) {
                objG3 = new C1280m(navigationManager, function0, 21);
                c0814p2.i0(objG3);
            }
            Function2 function2 = (Function2) objG3;
            c0814p2.p(false);
            c0814p2.X(2138156004);
            boolean zH = ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i2 & 896) == 256) | c0814p2.h(bVar) | c0814p2.h(addMaterialFolderData) | c0814p2.h(hD) | ((i2 & 14) == 4);
            Object objI2 = c0814p2.I();
            if (zH || objI2 == v) {
                H h4 = hD;
                a aVar = new a(source, str, bVar, addMaterialFolderData, h4, navigationManager, function0, function2, function1, cVar);
                h2 = h4;
                c0814p2.i0(aVar);
                objI2 = aVar;
            } else {
                h2 = hD;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            Q1.d(h2, "upload", null, (Function1) objI2, c0814p, 48, 12);
            h3 = h2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.e(navigationManager, source, str, bVar, addMaterialFolderData, h3, i, 4);
        }
    }

    public static final SpannableStringBuilder b(String stringToStyle, int i, String str, boolean z) {
        Iterable<i> styledStrings;
        Intrinsics.checkNotNullParameter(stringToStyle, "fullText");
        if (!z) {
            return AbstractC3088z1.b(stringToStyle, A.b(new h(stringToStyle, i)));
        }
        if (str == null || (styledStrings = A.b(new i(str))) == null) {
            styledStrings = K.a;
        }
        Intrinsics.checkNotNullParameter(stringToStyle, "stringToStyle");
        Intrinsics.checkNotNullParameter(styledStrings, "styledStrings");
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(stringToStyle);
        for (i iVar : styledStrings) {
            boolean zG = StringsKt.G(stringToStyle, iVar.a, false);
            String str2 = iVar.a;
            if (zG) {
                spannableStringBuilder.setSpan(new StyleSpan(1), StringsKt.M(stringToStyle, str2, 0, false, 6), str2.length() + StringsKt.M(stringToStyle, str2, 0, false, 6), 33);
            } else {
                timber.log.c.a.d(android.support.v4.media.session.a.l(str2, " not part of the whole string ", stringToStyle), new Object[0]);
            }
        }
        return spannableStringBuilder;
    }
}
