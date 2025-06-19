package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.K5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class K5 {
    public static final void a(final com.quizlet.features.infra.folder.create.coursefolder.data.m cardState, final String title, final com.quizlet.assembly.compose.modals.x modalState, final com.quizlet.assembly.compose.modals.x schoolModalState, final com.quizlet.features.infra.folder.create.data.b createFolderState, final Function1 onCreateCourseFolderEvent, final kotlinx.collections.immutable.b subFolders, final boolean z, final boolean z2, final Function1 onEditTag, final Function0 onAddTag, final Function0 onDismissRequest, InterfaceC0806l interfaceC0806l, final int i, final int i2) {
        int i3;
        int i4;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(cardState, "cardState");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        Intrinsics.checkNotNullParameter(schoolModalState, "schoolModalState");
        Intrinsics.checkNotNullParameter(createFolderState, "createFolderState");
        Intrinsics.checkNotNullParameter(onCreateCourseFolderEvent, "onCreateCourseFolderEvent");
        Intrinsics.checkNotNullParameter(subFolders, "subFolders");
        Intrinsics.checkNotNullParameter(onEditTag, "onEditTag");
        Intrinsics.checkNotNullParameter(onAddTag, "onAddTag");
        Intrinsics.checkNotNullParameter(onDismissRequest, "onDismissRequest");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1855060946);
        if ((i & 6) == 0) {
            i3 = ((i & 8) == 0 ? c0814p2.f(cardState) : c0814p2.h(cardState) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p2.f(title) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i3 |= (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0 ? c0814p2.f(modalState) : c0814p2.h(modalState) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i3 |= (i & 4096) == 0 ? c0814p2.f(schoolModalState) : c0814p2.h(schoolModalState) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p2.f(createFolderState) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i3 |= c0814p2.h(onCreateCourseFolderEvent) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i3 |= c0814p2.h(subFolders) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i3 |= c0814p2.g(z) ? 8388608 : 4194304;
        }
        if ((i & 100663296) == 0) {
            i3 |= c0814p2.g(z2) ? 67108864 : 33554432;
        }
        if ((i & 805306368) == 0) {
            i3 |= c0814p2.h(onEditTag) ? 536870912 : 268435456;
        }
        int i5 = i3;
        if ((i2 & 6) == 0) {
            i4 = i2 | (c0814p2.h(onAddTag) ? 4 : 2);
        } else {
            i4 = i2;
        }
        if ((i2 & 48) == 0) {
            i4 |= c0814p2.h(onDismissRequest) ? 32 : 16;
        }
        int i6 = i4;
        if ((i5 & 306783379) == 306783378 && (i6 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            kotlin.jvm.internal.F f = new kotlin.jvm.internal.F();
            Object[] objArr = new Object[0];
            com.quizlet.data.repository.explanations.myexplanations.a aVar = androidx.compose.ui.text.input.A.d;
            c0814p2.X(1282858717);
            boolean z3 = (i5 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI = c0814p2.I();
            if (z3 || objI == C0804k.a) {
                objI = new com.braze.ui.d(title, 26);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            InterfaceC0773a0 interfaceC0773a0C = L4.c(objArr, aVar, (Function0) objI, c0814p2);
            String strC = cardState.c();
            if (strC.length() == 0) {
                strC = title;
            }
            int length = strC.length();
            interfaceC0773a0C.setValue(new androidx.compose.ui.text.input.A(4, AbstractC3205m5.c(length, length), strC));
            c0814p = c0814p2;
            com.google.android.gms.internal.mlkit_vision_document_scanner.U5.a(modalState, androidx.compose.runtime.internal.e.e(678042780, new com.quizlet.features.infra.folder.create.composables.e(cardState, subFolders, z, z2, createFolderState, onCreateCourseFolderEvent, modalState, onDismissRequest, schoolModalState, onEditTag, onAddTag, interfaceC0773a0C, f), c0814p2), null, androidx.compose.runtime.internal.e.e(-1510850982, new com.quizlet.features.infra.folder.create.composables.f(cardState, modalState, subFolders, z, z2, createFolderState, onCreateCourseFolderEvent, schoolModalState, onEditTag, onAddTag, interfaceC0773a0C, f), c0814p2), com.quizlet.assembly.compose.modals.z.a, com.quizlet.assembly.compose.modals.A.a, null, false, onDismissRequest, c0814p, ((i5 >> 6) & 14) | 3128 | ((i6 << 21) & 234881024), 196);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.features.infra.folder.create.composables.b
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).intValue();
                    int iH = C0776c.H(i | 1);
                    int iH2 = C0776c.H(i2);
                    K5.a(cardState, title, modalState, schoolModalState, createFolderState, onCreateCourseFolderEvent, subFolders, z, z2, onEditTag, onAddTag, onDismissRequest, (InterfaceC0806l) obj, iH, iH2);
                    return Unit.a;
                }
            };
        }
    }

    public static final androidx.compose.ui.unit.d b(Context context) {
        float f = context.getResources().getConfiguration().fontScale;
        float f2 = context.getResources().getDisplayMetrics().density;
        androidx.compose.ui.unit.fontscaling.a aVarA = androidx.compose.ui.unit.fontscaling.b.a(f);
        if (aVarA == null) {
            aVarA = new androidx.compose.ui.unit.l(f);
        }
        return new androidx.compose.ui.unit.d(f2, f, aVarA);
    }

    public static final com.quizlet.ui.compose.animations.a c(kotlinx.collections.immutable.e list, long j, long j2, InterfaceC0806l interfaceC0806l) {
        Intrinsics.checkNotNullParameter(list, "list");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-965537713);
        c0814p.X(-1862586021);
        Object objI = c0814p.I();
        if (objI == C0804k.a) {
            objI = C0776c.z(list.get(0));
            c0814p.i0(objI);
        }
        InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
        c0814p.p(false);
        C0776c.f(c0814p, Unit.a, new com.quizlet.ui.compose.animations.b(new kotlin.jvm.internal.H(), list, interfaceC0773a0, null));
        androidx.compose.animation.core.J jG = AbstractC0240f.g(AbstractC0240f.p("LabelAnimation", c0814p, 0), 1.0f, DefinitionKt.NO_Float_VALUE, new androidx.compose.animation.core.I(new androidx.compose.animation.core.K0(1000, (androidx.compose.animation.core.B) null, 4), 2, 0), "LabelAnimation", c0814p, 4536, 0);
        com.quizlet.ui.compose.animations.a aVar = new com.quizlet.ui.compose.animations.a((String) interfaceC0773a0.getValue(), new androidx.compose.ui.graphics.I(kotlin.collections.B.j(new C0861v(C0861v.b(j, ((Number) jG.getValue()).floatValue())), new C0861v(C0861v.b(j2, ((Number) jG.getValue()).floatValue()))), null, 0L, 9187343241974906880L));
        c0814p.p(false);
        return aVar;
    }
}
