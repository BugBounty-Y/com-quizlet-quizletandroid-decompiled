package com.google.android.gms.internal.mlkit_vision_camera;

import android.content.Context;
import android.content.res.Resources;
import androidx.navigation.C1265a;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.sequences.Sequence;
import kotlinx.coroutines.C5036u;
import kotlinx.coroutines.DispatchException;
import kotlinx.coroutines.TimeoutCancellationException;

/* loaded from: classes2.dex */
public abstract class H1 {
    public static final /* synthetic */ int a = 0;

    public static String a(androidx.navigation.internal.d context, int i) {
        Intrinsics.checkNotNullParameter(context, "context");
        if (i <= 16777215) {
            return String.valueOf(i);
        }
        context.getClass();
        try {
            Context context2 = context.a;
            Intrinsics.d(context2);
            String resourceName = context2.getResources().getResourceName(i);
            Intrinsics.d(resourceName);
            return resourceName;
        } catch (Resources.NotFoundException unused) {
            return String.valueOf(i);
        }
    }

    public static Sequence b(androidx.navigation.B b) {
        Intrinsics.checkNotNullParameter(b, "<this>");
        return kotlin.sequences.n.c(new C1265a(7), b);
    }

    public static final Object c(kotlinx.coroutines.internal.p pVar, boolean z, kotlinx.coroutines.internal.p pVar2, Function2 function2) {
        Object c5036u;
        Object objV;
        try {
            if (function2 == null) {
                c5036u = kotlin.coroutines.intrinsics.h.c(function2, pVar2, pVar);
            } else {
                kotlin.jvm.internal.O.d(2, function2);
                c5036u = function2.invoke(pVar2, pVar);
            }
        } catch (DispatchException e) {
            Throwable th = e.a;
            pVar.U(new C5036u(th, false));
            throw th;
        } catch (Throwable th2) {
            c5036u = new C5036u(th2, false);
        }
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (c5036u == aVar || (objV = pVar.V(c5036u)) == kotlinx.coroutines.E.e) {
            return aVar;
        }
        pVar.n0();
        if (!(objV instanceof C5036u)) {
            return kotlinx.coroutines.E.I(objV);
        }
        if (!z) {
            Throwable th3 = ((C5036u) objV).a;
            if ((th3 instanceof TimeoutCancellationException) && ((TimeoutCancellationException) th3).a == pVar) {
                if (c5036u instanceof C5036u) {
                    throw ((C5036u) c5036u).a;
                }
                return c5036u;
            }
        }
        throw ((C5036u) objV).a;
    }
}
