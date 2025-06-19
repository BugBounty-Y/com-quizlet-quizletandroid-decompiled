package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.data.model.CreatedFolder;
import java.util.List;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class U5 {
    public static final void a(com.quizlet.assembly.compose.modals.x modalState, androidx.compose.ui.n nVar, Function1 function1, Function1 function12, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1494586463);
        int i2 = i | (c0814p.h(modalState) ? 4 : 2) | 48 | (c0814p.h(function1) ? 256 : 128) | (c0814p.h(function12) ? 2048 : 1024) | (c0814p.h(function0) ? 16384 : 8192);
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            c0814p.X(-1623737623);
            boolean z = true;
            boolean z2 = (i2 & 7168) == 2048;
            int i3 = i2 & 14;
            if (i3 != 4 && !c0814p.h(modalState)) {
                z = false;
            }
            boolean z3 = z2 | z;
            Object objI = c0814p.I();
            if (z3 || objI == v) {
                objI = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.y(function12, modalState, 0);
                c0814p.i0(objI);
            }
            Function1 function13 = (Function1) objI;
            c0814p.p(false);
            com.google.android.gms.internal.mlkit_vision_document_scanner.U5.a(modalState, androidx.compose.runtime.internal.e.e(-617751445, new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.z(function1, function13, modalState, 0), c0814p), null, androidx.compose.runtime.internal.e.e(362999337, new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.z(function1, function13, modalState, 1), c0814p), com.quizlet.assembly.compose.modals.z.a, com.quizlet.assembly.compose.modals.A.a, null, false, function0, c0814p, i3 | 3128 | ((i2 << 12) & 234881024), 196);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(modalState, nVar2, function1, function12, function0, i);
        }
    }

    public static String b(List list, String str, androidx.compose.ui.draganddrop.d dVar, int i) {
        if ((i & 1) != 0) {
            str = ", ";
        }
        if ((i & 32) != 0) {
            dVar = null;
        }
        StringBuilder sb = new StringBuilder();
        sb.append((CharSequence) "");
        int size = list.size();
        int i2 = 0;
        for (int i3 = 0; i3 < size; i3++) {
            Object obj = list.get(i3);
            i2++;
            if (i2 > 1) {
                sb.append((CharSequence) str);
            }
            if (dVar != null) {
                android.support.v4.media.session.a.A(obj);
                throw null;
            }
            if (obj != null ? obj instanceof CharSequence : true) {
                sb.append((CharSequence) obj);
            } else if (obj instanceof Character) {
                sb.append(((Character) obj).charValue());
            } else {
                sb.append((CharSequence) String.valueOf(obj));
            }
        }
        sb.append((CharSequence) "");
        return sb.toString();
    }

    public static final com.quizlet.ui.models.content.listitem.e c(CreatedFolder createdFolder) {
        Intrinsics.checkNotNullParameter(createdFolder, "<this>");
        return new com.quizlet.ui.models.content.listitem.e(createdFolder.a(), createdFolder.g());
    }
}
