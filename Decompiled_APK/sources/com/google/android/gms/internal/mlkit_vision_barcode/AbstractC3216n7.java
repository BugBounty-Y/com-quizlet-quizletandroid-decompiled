package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.AbstractC4383b;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Arrays;
import kotlin.Pair;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.n7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3216n7 {
    public static io.ktor.utils.io.z a(byte[] content) {
        int length = content.length;
        Intrinsics.checkNotNullParameter(content, "content");
        kotlinx.io.a source = new kotlinx.io.a();
        source.j(length, content);
        Intrinsics.checkNotNullParameter(source, "source");
        return new io.ktor.utils.io.z(source);
    }

    public static final void b(String currentTitle, boolean z, String str, Function1 function1, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        boolean z2 = z;
        Intrinsics.checkNotNullParameter(currentTitle, "currentTitle");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1406356749);
        int i2 = i | (c0814p.f(currentTitle) ? 4 : 2) | (c0814p.d(60) ? 32 : 16) | (c0814p.g(z2) ? 256 : 128) | (c0814p.f(str) ? 2048 : 1024) | (c0814p.h(function1) ? 16384 : 8192);
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            Object[] objArr = new Object[0];
            c0814p.X(1102161417);
            boolean z3 = (i2 & 14) == 4;
            Object objI = c0814p.I();
            if (z3 || objI == v) {
                objI = new com.braze.ui.d(currentTitle, 27);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI, c0814p, 0, 6);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.s();
            androidx.compose.ui.q qVarW = AbstractC0382e.w(nVar, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, 2);
            long jH = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.h();
            com.quizlet.features.folders.edittags.composables.f fVar = new com.quizlet.features.folders.edittags.composables.f(1, currentTitle, function1, interfaceC0773a0, z2);
            z2 = z2;
            androidx.compose.material3.Z1.a(function0, androidx.compose.runtime.internal.e.e(-1362409019, fVar, c0814p), qVarW, androidx.compose.runtime.internal.e.e(-890069373, new com.quizlet.explanations.textbook.ui.composables.i(z2, function0, 1), c0814p), AbstractC4383b.a, androidx.compose.runtime.internal.e.e(-181559904, new androidx.navigation.compose.o(23, interfaceC0773a0, str), c0814p), null, jH, 0L, 0L, 0L, DefinitionKt.NO_Float_VALUE, null, c0814p, 1772598, 0, 16016);
            c0814p = c0814p;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.listitems.b(currentTitle, z2, str, function1, function0, i);
        }
    }

    public static final androidx.glance.action.f c(androidx.glance.action.d... dVarArr) {
        ArrayList arrayList = new ArrayList(dVarArr.length);
        if (dVarArr.length <= 0) {
            Pair[] pairArr = (Pair[]) arrayList.toArray(new Pair[0]);
            return new androidx.glance.action.f(kotlin.collections.V.g((Pair[]) Arrays.copyOf(pairArr, pairArr.length)));
        }
        androidx.glance.action.d dVar = dVarArr[0];
        throw null;
    }
}
