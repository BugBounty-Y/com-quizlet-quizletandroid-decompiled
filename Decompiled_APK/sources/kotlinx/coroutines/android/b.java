package kotlinx.coroutines.android;

import kotlinx.coroutines.A;
import kotlinx.coroutines.C5041z;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.a implements A {
    private volatile Object _preHandler;

    public b() {
        super(C5041z.a);
        this._preHandler = this;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x002b  */
    @Override // kotlinx.coroutines.A
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void handleException(kotlin.coroutines.CoroutineContext r3, java.lang.Throwable r4) {
        /*
            r2 = this;
            int r3 = android.os.Build.VERSION.SDK_INT
            r0 = 28
            if (r3 >= r0) goto L46
            java.lang.Object r3 = r2._preHandler
            r0 = 0
            if (r3 == r2) goto Le
            java.lang.reflect.Method r3 = (java.lang.reflect.Method) r3
            goto L2e
        Le:
            java.lang.Class<java.lang.Thread> r3 = java.lang.Thread.class
            java.lang.String r1 = "getUncaughtExceptionPreHandler"
            java.lang.reflect.Method r3 = r3.getDeclaredMethod(r1, r0)     // Catch: java.lang.Throwable -> L2b
            int r1 = r3.getModifiers()     // Catch: java.lang.Throwable -> L2b
            boolean r1 = java.lang.reflect.Modifier.isPublic(r1)     // Catch: java.lang.Throwable -> L2b
            if (r1 == 0) goto L2b
            int r1 = r3.getModifiers()     // Catch: java.lang.Throwable -> L2b
            boolean r1 = java.lang.reflect.Modifier.isStatic(r1)     // Catch: java.lang.Throwable -> L2b
            if (r1 == 0) goto L2b
            goto L2c
        L2b:
            r3 = r0
        L2c:
            r2._preHandler = r3
        L2e:
            if (r3 == 0) goto L35
            java.lang.Object r3 = r3.invoke(r0, r0)
            goto L36
        L35:
            r3 = r0
        L36:
            boolean r1 = r3 instanceof java.lang.Thread.UncaughtExceptionHandler
            if (r1 == 0) goto L3d
            r0 = r3
            java.lang.Thread$UncaughtExceptionHandler r0 = (java.lang.Thread.UncaughtExceptionHandler) r0
        L3d:
            if (r0 == 0) goto L46
            java.lang.Thread r3 = java.lang.Thread.currentThread()
            r0.uncaughtException(r3, r4)
        L46:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.android.b.handleException(kotlin.coroutines.CoroutineContext, java.lang.Throwable):void");
    }
}
