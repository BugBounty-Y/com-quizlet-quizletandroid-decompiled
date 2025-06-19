package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.o5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3690o5 {
    public static final void a(String str, int i, InterfaceC0806l interfaceC0806l, int i2) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(368491673);
        int i3 = i2 | (c0814p2.f(str) ? 4 : 2) | (c0814p2.d(i) ? 32 : 16);
        if ((i3 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            Context context = (Context) c0814p2.j(AndroidCompositionLocals_androidKt.b);
            String string = context.getString(R.string.draft_set_formatter, (str == null || StringsKt.O(str)) ? context.getString(R.string.untitled_set) : str);
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(string, null, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).e, 0L, null, 0L, null, 0L, 2, false, i, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).g, c0814p, 0, ((i3 << 6) & 7168) | 48, 55290);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.f(str, i, i2, 0);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x0137  */
    /* JADX WARN: Removed duplicated region for block: B:102:0x013b  */
    /* JADX WARN: Removed duplicated region for block: B:105:0x0140  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x0145  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x0148  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x0166  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x0168  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x016d  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x0171  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x018f  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x01ab  */
    /* JADX WARN: Removed duplicated region for block: B:130:0x01ae  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x01bd  */
    /* JADX WARN: Removed duplicated region for block: B:138:0x01c9  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x0216  */
    /* JADX WARN: Removed duplicated region for block: B:146:0x0235  */
    /* JADX WARN: Removed duplicated region for block: B:148:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x004a  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x004f  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0065  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0077  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x007b  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0092  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x00b0  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00b5  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00ce A[PHI: r17
  0x00ce: PHI (r17v24 int) = (r17v6 int), (r17v12 int), (r17v13 int) binds: [B:71:0x00cc, B:81:0x00e9, B:80:0x00e6] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00d1  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x00f2  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x00f9  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x011a  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0133  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(final com.quizlet.ui.models.content.carditem.f r31, androidx.compose.ui.n r32, int r33, int r34, final kotlin.jvm.functions.c r35, boolean r36, kotlin.jvm.functions.Function0 r37, androidx.compose.runtime.internal.d r38, com.quizlet.ui.compose.util.a r39, kotlin.jvm.functions.Function0 r40, androidx.compose.runtime.InterfaceC0806l r41, final int r42, final int r43) {
        /*
            Method dump skipped, instructions count: 575
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3690o5.b(com.quizlet.ui.models.content.carditem.f, androidx.compose.ui.n, int, int, kotlin.jvm.functions.c, boolean, kotlin.jvm.functions.Function0, androidx.compose.runtime.internal.d, com.quizlet.ui.compose.util.a, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    public static final void c(String str, int i, InterfaceC0806l interfaceC0806l, int i2) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1811996496);
        int i3 = i2 | (c0814p2.f(str) ? 4 : 2) | (c0814p2.d(i) ? 32 : 16);
        if ((i3 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(str, null, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 2, false, i, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).g, c0814p, i3 & 14, ((i3 << 6) & 7168) | 48, 55290);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.f(str, i, i2, 1);
        }
    }
}
