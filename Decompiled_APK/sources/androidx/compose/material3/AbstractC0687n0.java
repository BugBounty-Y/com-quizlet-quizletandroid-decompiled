package androidx.compose.material3;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.text.C0490g0;
import androidx.compose.material3.internal.AbstractC0646j;
import androidx.compose.material3.internal.AbstractC0655t;
import androidx.compose.material3.internal.C0656u;
import androidx.compose.material3.internal.C0658w;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.time.chrono.Chronology;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.FormatStyle;
import java.util.Locale;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlin.text.MatchGroup;
import kotlin.text.Regex;
import kotlin.text.StringsKt;

/* renamed from: androidx.compose.material3.n0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0687n0 {
    public static final androidx.compose.foundation.layout.A0 a;
    public static final float b = 16;

    static {
        float f = 24;
        a = AbstractC0382e.e(f, 10, f, DefinitionKt.NO_Float_VALUE, 8);
    }

    public static final void a(Long l, Function1 function1, AbstractC0655t abstractC0655t, IntRange intRange, C0716s0 c0716s0, InterfaceC0764y3 interfaceC0764y3, C0699p0 c0699p0, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(643325609);
        int i2 = i | (c0814p.f(l) ? 4 : 2) | (c0814p.h(function1) ? 32 : 16) | (c0814p.h(abstractC0655t) ? 256 : 128) | (c0814p.h(intRange) ? 2048 : 1024) | (c0814p.f(c0716s0) ? 16384 : 8192) | (c0814p.f(interfaceC0764y3) ? 131072 : 65536) | (c0814p.f(c0699p0) ? 1048576 : 524288);
        if ((599187 & i2) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            Locale localeQ = Z1.q(c0814p);
            boolean zF = c0814p.f(localeQ);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (zF || objI == v) {
                ((C0656u) abstractC0655t).getClass();
                String strU = StringsKt.U(kotlin.text.D.o(new Regex("y{1,4}").replace(new Regex("M{1,2}").replace(new Regex("d{1,2}").replace(new Regex("[^dMy/\\-.]").replace(DateTimeFormatterBuilder.getLocalizedDateTimePattern(FormatStyle.SHORT, null, Chronology.ofLocale(localeQ), localeQ), ""), "dd"), "MM"), "yyyy"), "My", "M/y", false), ".");
                kotlin.text.m mVarB = new Regex("[/\\-.]").b(strU);
                Intrinsics.d(mVarB);
                MatchGroup matchGroupB = mVarB.c.b(0);
                Intrinsics.d(matchGroupB);
                int i3 = matchGroupB.b.a;
                String strSubstring = strU.substring(i3, i3 + 1);
                Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
                C0658w c0658w = new C0658w(strU, strSubstring.charAt(0));
                c0814p.i0(c0658w);
                objI = c0658w;
            }
            C0658w c0658w2 = (C0658w) objI;
            String strG = AbstractC0646j.g(c0814p, R.string.m3c_date_input_invalid_for_pattern);
            String strG2 = AbstractC0646j.g(c0814p, R.string.m3c_date_input_invalid_year_range);
            String strG3 = AbstractC0646j.g(c0814p, R.string.m3c_date_input_invalid_not_allowed);
            boolean zF2 = c0814p.f(c0658w2) | ((57344 & i2) == 16384);
            Object objI2 = c0814p.I();
            if (zF2 || objI2 == v) {
                C0693o0 c0693o0 = new C0693o0(intRange, interfaceC0764y3, c0658w2, c0716s0, strG, strG2, strG3);
                c0814p.i0(c0693o0);
                objI2 = c0693o0;
            }
            C0693o0 c0693o02 = (C0693o0) objI2;
            String upperCase = c0658w2.a.toUpperCase(Locale.ROOT);
            Intrinsics.checkNotNullExpressionValue(upperCase, "this as java.lang.String).toUpperCase(Locale.ROOT)");
            String strG4 = AbstractC0646j.g(c0814p, R.string.m3c_date_input_label);
            androidx.compose.ui.q qVarT = AbstractC0382e.t(androidx.compose.foundation.layout.K0.c(androidx.compose.ui.n.b, 1.0f), a);
            c0693o02.getClass();
            int i4 = i2 << 3;
            b(qVarT, l, function1, abstractC0655t, androidx.compose.runtime.internal.e.e(-1819015125, new androidx.compose.foundation.contextmenu.i(13, strG4, upperCase), c0814p), androidx.compose.runtime.internal.e.e(-564233108, new C0675l0(upperCase, 0), c0814p), c0693o02, c0658w2, localeQ, c0699p0, c0814p, (i4 & 7168) | (i4 & ContentType.LONG_FORM_ON_DEMAND) | 1794054 | (i4 & 896), (i2 >> 18) & 14);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.lazy.grid.n(l, function1, abstractC0655t, intRange, c0716s0, interfaceC0764y3, c0699p0, i);
        }
    }

    /* JADX WARN: Type inference failed for: r9v3 */
    /* JADX WARN: Type inference failed for: r9v4, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r9v5 */
    public static final void b(androidx.compose.ui.q qVar, Long l, Function1 function1, AbstractC0655t abstractC0655t, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, C0693o0 c0693o0, C0658w c0658w, Locale locale, C0699p0 c0699p0, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        int i4;
        Object o;
        int i5;
        int i6;
        int i7;
        Locale locale2;
        androidx.compose.runtime.V v;
        InterfaceC0773a0 interfaceC0773a0;
        ?? r9;
        int i8;
        C0658w c0658w2;
        C0814p c0814p;
        AbstractC0655t abstractC0655t2 = abstractC0655t;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-857008589);
        if ((i & 6) == 0) {
            i3 = (c0814p2.f(qVar) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p2.f(l) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i3 |= c0814p2.h(function1) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i3 |= c0814p2.h(abstractC0655t2) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p2.h(dVar) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i3 |= c0814p2.h(dVar2) ? 131072 : 65536;
        }
        if ((i & 1572864) == 0) {
            i3 |= c0814p2.d(0) ? 1048576 : 524288;
        }
        if ((i & 12582912) == 0) {
            i3 |= c0814p2.f(c0693o0) ? 8388608 : 4194304;
        }
        if ((i & 100663296) == 0) {
            i3 |= c0814p2.f(c0658w) ? 67108864 : 33554432;
        }
        if ((i & 805306368) == 0) {
            i3 |= c0814p2.h(locale) ? 536870912 : 268435456;
        }
        if ((i2 & 6) == 0) {
            i4 = i2 | (c0814p2.f(c0699p0) ? 4 : 2);
        } else {
            i4 = i2;
        }
        if ((i3 & 306783379) == 306783378 && (i4 & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            c0658w2 = c0658w;
            c0814p = c0814p2;
        } else {
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(new Object[0], null, C0584a0.e, c0814p2, 3072, 6);
            Object[] objArr = new Object[0];
            com.quizlet.data.repository.explanations.myexplanations.a aVar = androidx.compose.ui.text.input.A.d;
            int i9 = 234881024 & i3;
            boolean zH = ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32) | c0814p2.h(abstractC0655t2) | (i9 == 67108864) | c0814p2.h(locale);
            Object objI = c0814p2.I();
            androidx.compose.runtime.V v2 = C0804k.a;
            if (zH || objI == v2) {
                i5 = i9;
                i6 = 67108864;
                i7 = i3;
                o = new androidx.compose.animation.core.O(l, abstractC0655t2, c0658w, locale, 2);
                locale2 = locale;
                abstractC0655t2 = abstractC0655t2;
                c0814p2.i0(o);
            } else {
                i7 = i3;
                o = objI;
                locale2 = locale;
                i5 = i9;
                i6 = 67108864;
            }
            InterfaceC0773a0 interfaceC0773a0C = com.google.android.gms.internal.mlkit_vision_barcode.L4.c(objArr, aVar, (Function0) o, c0814p2);
            androidx.compose.ui.text.input.A a2 = (androidx.compose.ui.text.input.A) interfaceC0773a0C.getValue();
            boolean zF = (i5 == i6) | c0814p2.f(interfaceC0773a0C) | c0814p2.f(interfaceC0773a02) | ((i7 & 896) == 256) | c0814p2.h(abstractC0655t2) | ((29360128 & i7) == 8388608) | ((3670016 & i7) == 1048576) | c0814p2.h(locale2);
            Object objI2 = c0814p2.I();
            if (zF || objI2 == v2) {
                v = v2;
                interfaceC0773a0 = interfaceC0773a02;
                r9 = 0;
                i8 = i7;
                Locale locale3 = locale2;
                c0658w2 = c0658w;
                G g = new G(c0658w2, interfaceC0773a0, function1, abstractC0655t2, c0693o0, locale3, interfaceC0773a0C, 1);
                c0814p2.i0(g);
                objI2 = g;
            } else {
                c0658w2 = c0658w;
                v = v2;
                interfaceC0773a0 = interfaceC0773a02;
                r9 = 0;
                i8 = i7;
            }
            Function1 function12 = (Function1) objI2;
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, !StringsKt.O((CharSequence) interfaceC0773a0.getValue()) ? (float) r9 : b, 7);
            boolean zF2 = c0814p2.f(interfaceC0773a0);
            Object objI3 = c0814p2.I();
            if (zF2 || objI3 == v) {
                objI3 = new androidx.compose.foundation.gestures.T(interfaceC0773a0, 7);
                c0814p2.i0(objI3);
            }
            c0814p = c0814p2;
            AbstractC0587a3.a(a2, function12, androidx.compose.ui.semantics.m.a(qVarY, r9, (Function1) objI3), false, null, dVar, dVar2, androidx.compose.runtime.internal.e.e(-591991974, new C0674l(interfaceC0773a0, 1), c0814p2), !StringsKt.O((CharSequence) interfaceC0773a0.getValue()), new C0591b1(c0658w2), new C0490g0(3, 7, ContentType.LIVE), null, true, 0, 0, null, c0699p0.y, c0814p, (i8 << 6) & 33030144);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0681m0(qVar, l, function1, abstractC0655t, dVar, dVar2, c0693o0, c0658w2, locale, c0699p0, i, i2);
        }
    }
}
