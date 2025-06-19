package com.braze.support.delegates;

import androidx.navigation.compose.C1277j;
import com.braze.support.BrazeLogger;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.n;

/* loaded from: classes.dex */
public final class a {
    public Object a;

    public static final String a(Object obj, n nVar) {
        return "Cannot assign " + obj + " to only-set-once property " + nVar.getName();
    }

    public final void setValue(Object thisRef, n property, Object obj) {
        Intrinsics.checkNotNullParameter(thisRef, "thisRef");
        Intrinsics.checkNotNullParameter(property, "property");
        Object obj2 = this.a;
        if (obj2 == null) {
            this.a = obj;
        } else {
            if (obj2.equals(obj)) {
                return;
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1277j(28, obj, property), 7, (Object) null);
        }
    }
}
