package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.layout.FillElement;
import androidx.compose.foundation.layout.InterfaceC0388h;
import androidx.compose.foundation.layout.InterfaceC0394k;
import androidx.compose.foundation.lazy.grid.C0426a;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3155h0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.library.C4660e;
import com.quizlet.quizletandroid.ui.library.C4661f;
import com.quizlet.quizletandroid.ui.library.data.C4653g;
import com.quizlet.quizletandroid.ui.library.data.C4654h;
import com.quizlet.quizletandroid.ui.library.data.C4655i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Z4 {
    public static final void a(kotlinx.collections.immutable.e eVar, Function1 function1, Function1 function12, boolean z, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function1 function13;
        Function1 function14;
        androidx.compose.foundation.lazy.grid.A a;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1536107329);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(eVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            function13 = function1;
            i2 |= c0814p2.h(function13) ? 32 : 16;
        } else {
            function13 = function1;
        }
        if ((i & 384) == 0) {
            function14 = function12;
            i2 |= c0814p2.h(function14) ? 256 : 128;
        } else {
            function14 = function12;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.g(z) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            int iD = AbstractC3706q5.d(AbstractC3205m5.g(c0814p2).a);
            androidx.compose.foundation.lazy.grid.A a2 = androidx.compose.foundation.lazy.grid.B.a(0, c0814p2, 3);
            C0426a c0426a = new C0426a(iD);
            androidx.compose.foundation.layout.A0 a0C = AbstractC3706q5.c(z, c0814p2);
            InterfaceC0394k interfaceC0394kE = AbstractC3706q5.e(z);
            InterfaceC0388h interfaceC0388hB = AbstractC3706q5.b(z);
            FillElement fillElement = androidx.compose.foundation.layout.K0.c;
            c0814p2.X(-1670431419);
            boolean zH = ((i2 & 896) == 256) | c0814p2.h(eVar) | c0814p2.f(a2) | ((i2 & 7168) == 2048) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32);
            Object objI = c0814p2.I();
            if (zH || objI == v) {
                C4660e c4660e = new C4660e(eVar, a2, function14, z, function13, 1);
                a = a2;
                c0814p2.i0(c4660e);
                objI = c4660e;
            } else {
                a = a2;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC3155h0.b(c0426a, fillElement, a, a0C, interfaceC0394kE, interfaceC0388hB, null, false, (Function1) objI, c0814p, 48, 400);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4661f(eVar, function1, function12, z, i, 1);
        }
    }

    public static final void b(AbstractC3690o5 data, Function0 function0, Function1 function1, Function1 function12, boolean z, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(data, "data");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1269393883);
        int i2 = i | (c0814p.f(data) ? 4 : 2) | (c0814p.h(function0) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128) | (c0814p.h(function12) ? 2048 : 1024) | (c0814p.g(z) ? 16384 : 8192);
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else if (data instanceof C4653g) {
            c0814p.X(-497340981);
            a(((C4653g) data).a, function1, function12, z, c0814p, (i2 >> 3) & 8176);
            c0814p = c0814p;
            c0814p.p(false);
        } else if (Intrinsics.b(data, C4655i.a)) {
            c0814p.X(-497332933);
            AbstractC3249r5.a(null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), c0814p, 0, 1);
            c0814p.p(false);
        } else {
            if (!Intrinsics.b(data, C4654h.a)) {
                throw com.google.android.gms.measurement.internal.Z.j(-497342130, c0814p, false);
            }
            c0814p.X(1762667551);
            com.quizlet.themes.e.a(c0814p).d.getClass();
            c0814p.X(-1234381252);
            androidx.compose.ui.graphics.painter.b bVarA = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(R.drawable.ic_brand_folder, c0814p, 0);
            c0814p.p(false);
            AbstractC3611e6.a(bVarA, AbstractC3106b5.d(c0814p, R.string.library_create_folder_description), AbstractC3106b5.d(c0814p, R.string.library_create_folder_button), null, AbstractC3106b5.d(c0814p, R.string.library_create_folder_content_description), function0, c0814p, (i2 << 12) & 458752);
            c0814p = c0814p;
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.listitems.b(data, function0, function1, function12, z, i, 10);
        }
    }
}
