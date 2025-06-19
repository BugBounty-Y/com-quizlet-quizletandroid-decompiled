package kotlinx.coroutines.internal;

import androidx.glance.appwidget.protobuf.Z;

/* loaded from: classes3.dex */
public abstract class r {
    public static final /* synthetic */ int a = 0;

    static {
        Object objB;
        Object objB2;
        Exception exc = new Exception();
        String simpleName = _COROUTINE.a.class.getSimpleName();
        StackTraceElement stackTraceElement = exc.getStackTrace()[0];
        new StackTraceElement("_COROUTINE.".concat(simpleName), "_", stackTraceElement.getFileName(), stackTraceElement.getLineNumber());
        try {
            kotlin.p pVar = kotlin.r.b;
            objB = kotlin.coroutines.jvm.internal.a.class.getCanonicalName();
        } catch (Throwable th) {
            kotlin.p pVar2 = kotlin.r.b;
            objB = Z.b(th);
        }
        if (kotlin.r.a(objB) != null) {
            objB = "kotlin.coroutines.jvm.internal.BaseContinuationImpl";
        }
        try {
            objB2 = r.class.getCanonicalName();
        } catch (Throwable th2) {
            kotlin.p pVar3 = kotlin.r.b;
            objB2 = Z.b(th2);
        }
        if (kotlin.r.a(objB2) != null) {
            objB2 = "kotlinx.coroutines.internal.StackTraceRecoveryKt";
        }
    }
}
