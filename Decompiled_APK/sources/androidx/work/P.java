package androidx.work;

import android.content.Context;
import android.content.ContextWrapper;
import android.text.format.DateFormat;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import com.quizlet.data.model.C4106a;
import com.quizlet.data.model.C4114c;
import com.quizlet.data.model.EnumC4110b;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Locale;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class P {
    public static final String d(C4114c c4114c) {
        Intrinsics.checkNotNullParameter(c4114c, "<this>");
        DateTimeFormatter dateTimeFormatterOfPattern = DateTimeFormatter.ofPattern(DateFormat.getBestDateTimePattern(Locale.getDefault(), "dd/MM/yyyy"), Locale.getDefault());
        LocalDate localDate = c4114c.h;
        if (localDate != null) {
            return localDate.format(dateTimeFormatterOfPattern);
        }
        return null;
    }

    public static boolean e(int i, com.quizlet.time.c cVar, int i2, int i3) {
        GregorianCalendar gregorianCalendar = new GregorianCalendar();
        GregorianCalendar gregorianCalendar2 = new GregorianCalendar(i + i3, cVar.a, i2);
        return gregorianCalendar2.before(gregorianCalendar) || gregorianCalendar2.equals(gregorianCalendar);
    }

    public static final androidx.activity.compose.o f(androidx.activity.result.contract.a aVar, Function1 function1, InterfaceC0806l interfaceC0806l) {
        Object dVar;
        Object obj;
        C0776c.D(aVar, interfaceC0806l);
        Object objD = C0776c.D(function1, interfaceC0806l);
        Object obj2 = (String) L4.d(new Object[0], null, androidx.activity.compose.e.b, interfaceC0806l, 3072, 6);
        C0814p c0814p = (C0814p) interfaceC0806l;
        androidx.activity.result.i iVar = (androidx.activity.result.i) c0814p.j(androidx.activity.compose.m.a);
        if (iVar == null) {
            c0814p.X(1006590171);
            Object baseContext = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
            while (true) {
                if (!(baseContext instanceof ContextWrapper)) {
                    baseContext = null;
                    break;
                }
                if (baseContext instanceof androidx.activity.result.i) {
                    break;
                }
                baseContext = ((ContextWrapper) baseContext).getBaseContext();
            }
            iVar = (androidx.activity.result.i) baseContext;
        } else {
            c0814p.X(1006589303);
        }
        c0814p.p(false);
        if (iVar == null) {
            throw new IllegalStateException("No ActivityResultRegistryOwner was provided via LocalActivityResultRegistryOwner");
        }
        Object activityResultRegistry = iVar.getActivityResultRegistry();
        Object objI = c0814p.I();
        Object obj3 = C0804k.a;
        if (objI == obj3) {
            objI = new androidx.activity.compose.a();
            c0814p.i0(objI);
        }
        androidx.activity.compose.a aVar2 = (androidx.activity.compose.a) objI;
        Object objI2 = c0814p.I();
        if (objI2 == obj3) {
            objI2 = new androidx.activity.compose.o(aVar2);
            c0814p.i0(objI2);
        }
        androidx.activity.compose.o oVar = (androidx.activity.compose.o) objI2;
        boolean zH = c0814p.h(aVar2) | c0814p.h(activityResultRegistry) | c0814p.f(obj2) | c0814p.h(aVar) | c0814p.f(objD);
        Object objI3 = c0814p.I();
        if (zH || objI3 == obj3) {
            obj = aVar;
            dVar = new androidx.activity.compose.d(aVar2, activityResultRegistry, obj2, obj, objD, 0);
            c0814p.i0(dVar);
        } else {
            dVar = objI3;
            obj = aVar;
        }
        Function1 function12 = (Function1) dVar;
        boolean zF = c0814p.f(activityResultRegistry) | c0814p.f(obj2) | c0814p.f(obj);
        Object objI4 = c0814p.I();
        if (zF || objI4 == obj3) {
            objI4 = new androidx.compose.runtime.F(function12);
            c0814p.i0(objI4);
        }
        return oVar;
    }

    public static final C4114c g(C4106a c4106a) {
        EnumC4110b enumC4110bValueOf;
        Intrinsics.checkNotNullParameter(c4106a, "<this>");
        String str = c4106a.a;
        LocalDate localDate = null;
        Long l = c4106a.i;
        boolean z = ((l != null && (l.longValue() > 0L ? 1 : (l.longValue() == 0L ? 0 : -1)) == 0) ? null : l) != null;
        String str2 = c4106a.h;
        if (str2 != null) {
            String upperCase = str2.toUpperCase(Locale.ROOT);
            Intrinsics.checkNotNullExpressionValue(upperCase, "toUpperCase(...)");
            enumC4110bValueOf = EnumC4110b.valueOf(upperCase);
        } else {
            enumC4110bValueOf = null;
        }
        if (l != null && l.longValue() == 0) {
            l = null;
        }
        if (l != null) {
            ZonedDateTime zonedDateTimeAtZone = Instant.ofEpochSecond(l.longValue()).atZone(ZoneId.systemDefault());
            Intrinsics.checkNotNullExpressionValue(zonedDateTimeAtZone, "atZone(...)");
            localDate = zonedDateTimeAtZone.toLocalDate();
        }
        return new C4114c(str, c4106a.d, z, c4106a.f, c4106a.b, c4106a.g, enumC4110bValueOf, localDate);
    }

    public androidx.work.impl.n a(String uniqueWorkName, EnumC1441o existingWorkPolicy, D request) {
        Intrinsics.checkNotNullParameter(uniqueWorkName, "uniqueWorkName");
        Intrinsics.checkNotNullParameter(existingWorkPolicy, "existingWorkPolicy");
        Intrinsics.checkNotNullParameter(request, "request");
        List listB = kotlin.collections.A.b(request);
        androidx.work.impl.r rVar = (androidx.work.impl.r) this;
        if (listB.isEmpty()) {
            throw new IllegalArgumentException("beginUniqueWork needs at least one OneTimeWorkRequest.");
        }
        return new androidx.work.impl.n(rVar, uniqueWorkName, existingWorkPolicy, listB);
    }

    public void b(D request) {
        Intrinsics.checkNotNullParameter(request, "request");
        List listB = kotlin.collections.A.b(request);
        androidx.work.impl.r rVar = (androidx.work.impl.r) this;
        if (listB.isEmpty()) {
            throw new IllegalArgumentException("enqueue needs at least one WorkRequest.");
        }
        new androidx.work.impl.n(rVar, null, EnumC1441o.b, listB).c();
    }

    public G c(String uniqueWorkName, EnumC1441o existingWorkPolicy, D request) {
        Intrinsics.checkNotNullParameter(uniqueWorkName, "uniqueWorkName");
        Intrinsics.checkNotNullParameter(existingWorkPolicy, "existingWorkPolicy");
        Intrinsics.checkNotNullParameter(request, "request");
        return new androidx.work.impl.n((androidx.work.impl.r) this, uniqueWorkName, existingWorkPolicy, kotlin.collections.A.b(request)).c();
    }
}
