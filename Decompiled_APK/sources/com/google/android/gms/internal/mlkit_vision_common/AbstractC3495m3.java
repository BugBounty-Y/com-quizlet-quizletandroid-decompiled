package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.comscore.streaming.ContentType;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3745v5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.m3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3495m3 {
    public static final void a(com.quizlet.features.settings.data.models.h updatePasswordType, androidx.compose.ui.q qVar, com.quizlet.features.settings.data.states.h hVar, String str, Function1 function1, String str2, Function1 function12, String str3, Function1 function13, com.quizlet.assembly.compose.input.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.assembly.compose.input.n nVar2;
        C0814p c0814p;
        androidx.compose.ui.n nVar3;
        boolean z;
        C0814p c0814p2;
        com.quizlet.assembly.compose.input.n nVar4;
        com.quizlet.qutils.string.g gVar;
        com.quizlet.qutils.string.g gVar2;
        com.quizlet.qutils.string.g gVar3;
        Intrinsics.checkNotNullParameter(updatePasswordType, "updatePasswordType");
        C0814p c0814p3 = (C0814p) interfaceC0806l;
        c0814p3.Z(-582693467);
        int i3 = i | (c0814p3.f(updatePasswordType) ? 4 : 2) | (c0814p3.f(qVar) ? 32 : 16) | (c0814p3.f(hVar) ? 256 : 128) | (c0814p3.f(str) ? 2048 : 1024) | (c0814p3.h(function1) ? 16384 : 8192) | (c0814p3.f(str2) ? 131072 : 65536) | (c0814p3.h(function12) ? 1048576 : 524288) | (c0814p3.f(str3) ? 8388608 : 4194304) | (c0814p3.h(function13) ? 67108864 : 33554432) | 268435456;
        if ((306783379 & i3) == 306783378 && c0814p3.x()) {
            c0814p3.Q();
            nVar4 = nVar;
            c0814p2 = c0814p3;
        } else {
            c0814p3.S();
            if ((i & 1) == 0 || c0814p3.w()) {
                i2 = i3 & (-1879048193);
                nVar2 = com.quizlet.assembly.compose.input.n.a;
            } else {
                c0814p3.Q();
                i2 = i3 & (-1879048193);
                nVar2 = nVar;
            }
            int i4 = i2;
            c0814p3.q();
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m.g.s();
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.h), androidx.compose.ui.b.m, c0814p3, 0);
            int i5 = c0814p3.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p3.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p3, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p3.b0();
            if (c0814p3.O) {
                c0814p3.k(c0913i);
            } else {
                c0814p3.l0();
            }
            C0776c.E(c0814p3, bA, C0914j.f);
            C0776c.E(c0814p3, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p3.O || !Intrinsics.b(c0814p3.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p3, i5, c0912h);
            }
            C0776c.E(c0814p3, qVarC, C0914j.d);
            c0814p3.X(266086575);
            com.quizlet.features.settings.data.models.h hVar2 = com.quizlet.features.settings.data.models.h.a;
            androidx.compose.ui.n nVar5 = androidx.compose.ui.n.b;
            String strA = null;
            if (updatePasswordType == hVar2) {
                androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar5, "UpdatePasswordContent.currentPasswordInput");
                String strD = AbstractC3106b5.d(c0814p3, R.string.current_password_hint);
                c0814p3.X(266099180);
                String strA2 = (!(hVar instanceof com.quizlet.features.settings.data.states.e) || (gVar3 = ((com.quizlet.features.settings.data.states.e) hVar).c) == null) ? null : gVar3.a((Context) c0814p3.j(AndroidCompositionLocals_androidKt.b));
                c0814p3.p(false);
                int i6 = i4 >> 21;
                nVar3 = nVar5;
                z = false;
                AbstractC3745v5.b(str3, function13, qVarG, null, strD, 0, 0, null, 0, 7, null, strA2, false, null, null, hVar instanceof com.quizlet.features.settings.data.states.g, 0, nVar2, DefinitionKt.NO_Float_VALUE, null, null, c0814p3, (i6 & 14) | 384 | (i6 & ContentType.LONG_FORM_ON_DEMAND), 48, 0, 30922728);
                c0814p = c0814p3;
            } else {
                c0814p = c0814p3;
                nVar3 = nVar5;
                z = false;
            }
            c0814p.p(z);
            androidx.compose.ui.q qVarG2 = androidx.compose.ui.platform.N.G(nVar3, "UpdatePasswordContent.newPasswordInput");
            String strD2 = AbstractC3106b5.d(c0814p, R.string.new_password_hint);
            c0814p.X(266119164);
            boolean z2 = hVar instanceof com.quizlet.features.settings.data.states.e;
            String strA3 = (!z2 || (gVar2 = ((com.quizlet.features.settings.data.states.e) hVar).a) == null) ? null : gVar2.a((Context) c0814p.j(AndroidCompositionLocals_androidKt.b));
            c0814p.p(z);
            boolean z3 = hVar instanceof com.quizlet.features.settings.data.states.g;
            int i7 = i4 >> 9;
            C0814p c0814p4 = c0814p;
            AbstractC3745v5.b(str, function1, qVarG2, null, strD2, 0, 0, null, 0, 7, null, strA3, false, null, null, z3, 0, nVar2, DefinitionKt.NO_Float_VALUE, null, null, c0814p4, (i7 & 14) | 384 | (i7 & ContentType.LONG_FORM_ON_DEMAND), 48, 0, 30922728);
            androidx.compose.ui.q qVarG3 = androidx.compose.ui.platform.N.G(nVar3, "UpdatePasswordContent.confirmPasswordInput");
            String strD3 = AbstractC3106b5.d(c0814p4, R.string.confirm_password_hint);
            c0814p4.X(266138336);
            if (z2 && (gVar = ((com.quizlet.features.settings.data.states.e) hVar).b) != null) {
                strA = gVar.a((Context) c0814p4.j(AndroidCompositionLocals_androidKt.b));
            }
            String str4 = strA;
            c0814p4.p(z);
            int i8 = i4 >> 15;
            AbstractC3745v5.b(str2, function12, qVarG3, null, strD3, 0, 0, null, 0, 7, null, str4, false, null, null, z3, 0, nVar2, DefinitionKt.NO_Float_VALUE, null, null, c0814p4, (i8 & 14) | 384 | (i8 & ContentType.LONG_FORM_ON_DEMAND), 48, 0, 30922728);
            c0814p2 = c0814p4;
            c0814p2.p(true);
            nVar4 = nVar2;
        }
        C0813o0 c0813o0R = c0814p2.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.detail.c(updatePasswordType, qVar, hVar, str, function1, str2, function12, str3, function13, nVar4, i);
        }
    }

    public static SafeParcelable b(byte[] bArr, Parcelable.Creator creator) {
        com.google.android.gms.common.internal.u.h(creator);
        Parcel parcelObtain = Parcel.obtain();
        parcelObtain.unmarshall(bArr, 0, bArr.length);
        parcelObtain.setDataPosition(0);
        SafeParcelable safeParcelable = (SafeParcelable) creator.createFromParcel(parcelObtain);
        parcelObtain.recycle();
        return safeParcelable;
    }
}
