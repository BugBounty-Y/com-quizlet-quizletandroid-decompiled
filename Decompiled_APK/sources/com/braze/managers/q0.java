package com.braze.managers;

import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.support.BrazeLogger;
import kotlin.Unit;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlin.text.StringsKt__StringsKt;

/* loaded from: classes.dex */
public final /* synthetic */ class q0 extends C4956o implements kotlin.jvm.functions.d {
    public q0(s0 s0Var) {
        super(4, 0, s0.class, s0Var, "log", "log$android_sdk_base_release(Ljava/lang/String;Lcom/braze/support/BrazeLogger$Priority;Ljava/lang/String;Ljava/lang/Throwable;)V");
    }

    @Override // kotlin.jvm.functions.d
    public final Object invoke(Object obj, Object obj2, Object obj3, Object obj4) {
        String tag = (String) obj;
        BrazeLogger.Priority priority = (BrazeLogger.Priority) obj2;
        String message = (String) obj3;
        Object obj5 = (Throwable) obj4;
        Intrinsics.checkNotNullParameter(tag, "p0");
        Intrinsics.checkNotNullParameter(priority, "p1");
        Intrinsics.checkNotNullParameter(message, "p2");
        s0 s0Var = (s0) this.receiver;
        s0Var.getClass();
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(priority, "priority");
        Intrinsics.checkNotNullParameter(message, "message");
        if (s0Var.c.a && !StringsKt.G(message, "Braze v36.0.0 .", false)) {
            StringBuilder sb = new StringBuilder();
            sb.append(priority);
            sb.append(' ');
            sb.append(tag);
            sb.append(": ");
            sb.append(message);
            sb.append(' ');
            String str = "";
            if (obj5 == null) {
                obj5 = "";
            }
            sb.append(obj5);
            for (String str2 : StringsKt__StringsKt.split$default(sb.toString(), new String[]{"\n"}, false, 0, 6, null)) {
                if (str2.length() + str.length() > s0Var.c.f) {
                    s0Var.a(priority + ": " + str);
                    str = str2;
                } else {
                    str = str + '\n' + str2;
                }
            }
            if (str.length() > 0) {
                s0Var.a(str);
            }
            kotlinx.coroutines.E.A(BrazeCoroutineScope.INSTANCE, null, null, new r0(s0Var, null), 3);
        }
        return Unit.a;
    }
}
