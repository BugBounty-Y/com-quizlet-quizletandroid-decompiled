package com.braze.requests;

import androidx.compose.ui.node.B;
import com.braze.managers.E;
import com.braze.support.BrazeLogger;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public abstract class c {
    public static void a(Object obj, Function0 function0) {
        try {
            function0.invoke();
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, obj, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new E(obj, 1), 4, (Object) null);
        }
    }

    public static final String a(Object obj) {
        return B.e(obj, "Encountered exception while parsing server response for ");
    }
}
