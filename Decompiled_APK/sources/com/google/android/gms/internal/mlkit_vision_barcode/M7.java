package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.quizletandroid.R;
import kotlin.Pair;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class M7 {
    public static com.google.android.gms.internal.mlkit_common.r a;

    public static final void a(androidx.glance.p pVar, androidx.glance.layout.c cVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1959221577);
        int i4 = (c0814p.f(pVar) ? 4 : 2) | i;
        int i5 = i2 & 2;
        if (i5 != 0) {
            i3 = i4 | 48;
        } else {
            i3 = i4 | (c0814p.f(cVar) ? 32 : 16);
        }
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            if (i5 != 0) {
                cVar = androidx.glance.layout.c.c;
            }
            androidx.glance.layout.d dVar2 = androidx.glance.layout.d.a;
            c0814p.Y(578571862);
            c0814p.Y(-548224868);
            if (!(c0814p.a instanceof androidx.glance.b)) {
                C0776c.s();
                throw null;
            }
            c0814p.V();
            if (c0814p.O) {
                c0814p.k(dVar2);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, pVar, androidx.glance.layout.e.b);
            C0776c.E(c0814p, cVar, androidx.glance.layout.e.c);
            dVar.invoke(c0814p, 6);
            c0814p.p(true);
            c0814p.p(false);
            c0814p.p(false);
        }
        androidx.glance.layout.c cVar2 = cVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.contextmenu.a(pVar, cVar2, dVar, i, i2);
        }
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, com.quizlet.data.model.m2 source, Function0 function0, Function0 function02) {
        int i2;
        Intrinsics.checkNotNullParameter(source, "source");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(286053930);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(source) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function02) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.google.android.gms.internal.mlkit_vision_document_scanner.W5.a(R.string.magic_notes_being_generated_cta, R.string.magic_notes_being_generated_desc, null, function0, function02, null, Integer.valueOf(source == com.quizlet.data.model.m2.a ? R.string.magic_notes_being_generated : R.string.flashcards_being_generated), Integer.valueOf(R.string.notes_cancel_button), c0814p, (i2 << 6) & 64512, 36);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 19, source, function0, function02);
        }
    }

    public static final Pair c(Object obj, Object obj2) {
        return new Pair(obj, obj2);
    }

    public static synchronized J7 d(String str) {
        J7 j7;
        byte b = (byte) (((byte) (0 | 1)) | 2);
        if (b != 3) {
            StringBuilder sb = new StringBuilder();
            if ((b & 1) == 0) {
                sb.append(" enableFirelog");
            }
            if ((b & 2) == 0) {
                sb.append(" firelogEventType");
            }
            throw new IllegalStateException("Missing required properties:".concat(sb.toString()));
        }
        F7 f7 = new F7(str, 1);
        synchronized (M7.class) {
            try {
                if (a == null) {
                    a = new com.google.android.gms.internal.mlkit_common.r(1);
                }
                j7 = (J7) a.p(f7);
            } catch (Throwable th) {
                throw th;
            }
        }
        return j7;
        return j7;
    }
}
