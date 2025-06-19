package androidx.compose.material3.internal;

import android.content.Context;
import android.text.format.DateFormat;
import androidx.compose.animation.d0;
import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.u0;
import androidx.compose.material.C0560c;
import androidx.compose.material3.AbstractC0669k0;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0811n0;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.comscore.streaming.ContentType;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DecimalStyle;
import java.util.LinkedHashMap;
import java.util.Locale;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.internal.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0646j {
    public static final androidx.compose.ui.text.y a = new androidx.compose.ui.text.y(null, new androidx.compose.ui.text.w());

    public static final void a(long j, androidx.compose.ui.text.L l, Function2 function2, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-716124955);
        if ((i & 6) == 0) {
            i2 = (c0814p.e(j) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(l) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function2) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.B b = Q4.a;
            C0776c.b(new C0811n0[]{d0.j(j, AbstractC0669k0.a), b.a(((androidx.compose.ui.text.L) c0814p.j(b)).e(l))}, function2, c0814p, ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | 8);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new N(j, l, function2, i, 0);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object b(kotlin.jvm.functions.Function0 r4, kotlin.jvm.functions.Function2 r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            boolean r0 = r6 instanceof androidx.compose.material3.internal.C0642f
            if (r0 == 0) goto L13
            r0 = r6
            androidx.compose.material3.internal.f r0 = (androidx.compose.material3.internal.C0642f) r0
            int r1 = r0.k
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.k = r1
            goto L18
        L13:
            androidx.compose.material3.internal.f r0 = new androidx.compose.material3.internal.f
            r0.<init>(r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.k
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: androidx.compose.material3.internal.C0639c -> L41
            goto L41
        L27:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            androidx.compose.material3.internal.i r6 = new androidx.compose.material3.internal.i     // Catch: androidx.compose.material3.internal.C0639c -> L41
            r2 = 0
            r6.<init>(r4, r5, r2)     // Catch: androidx.compose.material3.internal.C0639c -> L41
            r0.k = r3     // Catch: androidx.compose.material3.internal.C0639c -> L41
            java.lang.Object r4 = kotlinx.coroutines.E.m(r6, r0)     // Catch: androidx.compose.material3.internal.C0639c -> L41
            if (r4 != r1) goto L41
            return r1
        L41:
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.internal.AbstractC0646j.b(kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function2, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final Object c(androidx.work.impl.model.t tVar, Object obj, float f, kotlin.coroutines.jvm.internal.i iVar) {
        Object objD = tVar.d(obj, u0.a, new C0560c(tVar, f, null, 1), iVar);
        return objD == kotlin.coroutines.intrinsics.a.a ? objD : Unit.a;
    }

    public static final androidx.compose.ui.q d(androidx.compose.ui.q qVar, androidx.work.impl.model.t tVar, EnumC0320d0 enumC0320d0, Function2 function2) {
        return qVar.g(new DraggableAnchorsElement(tVar, function2, enumC0320d0));
    }

    public static String e(long j, String str, Locale locale, LinkedHashMap linkedHashMap) {
        String str2 = "P:" + str + locale.toLanguageTag();
        Object objWithDecimalStyle = linkedHashMap.get(str2);
        if (objWithDecimalStyle == null) {
            objWithDecimalStyle = DateTimeFormatter.ofPattern(str, locale).withDecimalStyle(DecimalStyle.of(locale));
            linkedHashMap.put(str2, objWithDecimalStyle);
        }
        Intrinsics.e(objWithDecimalStyle, "null cannot be cast to non-null type java.time.format.DateTimeFormatter");
        return Instant.ofEpochMilli(j).atZone(C0656u.d).toLocalDate().format((DateTimeFormatter) objWithDecimalStyle);
    }

    public static final String f(long j, String str, Locale locale, LinkedHashMap linkedHashMap) {
        String str2 = "S:" + str + locale.toLanguageTag();
        Object bestDateTimePattern = linkedHashMap.get(str2);
        if (bestDateTimePattern == null) {
            bestDateTimePattern = DateFormat.getBestDateTimePattern(locale, str);
            linkedHashMap.put(str2, bestDateTimePattern);
        }
        String string = bestDateTimePattern.toString();
        ZoneId zoneId = C0656u.d;
        return e(j, string, locale, linkedHashMap);
    }

    public static final String g(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.j(AndroidCompositionLocals_androidKt.a);
        return ((Context) c0814p.j(AndroidCompositionLocals_androidKt.b)).getResources().getString(i);
    }
}
