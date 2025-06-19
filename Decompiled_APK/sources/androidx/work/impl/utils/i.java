package androidx.work.impl.utils;

import android.app.ActivityManager;
import android.content.Context;
import android.os.Build;
import android.os.Process;
import androidx.work.C1422c;
import androidx.work.P;
import androidx.work.z;
import java.lang.reflect.Method;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class i {
    static {
        Intrinsics.checkNotNullExpressionValue(z.e("ProcessUtils"), "tagWithPrefix(\"ProcessUtils\")");
    }

    public static final boolean a(Context context, C1422c configuration) {
        String strF;
        Object next;
        Object objInvoke;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(configuration, "configuration");
        if (Build.VERSION.SDK_INT >= 28) {
            strF = androidx.arch.core.executor.d.f();
        } else {
            strF = null;
            try {
                Method declaredMethod = Class.forName("android.app.ActivityThread", false, P.class.getClassLoader()).getDeclaredMethod("currentProcessName", null);
                declaredMethod.setAccessible(true);
                objInvoke = declaredMethod.invoke(null, null);
                Intrinsics.d(objInvoke);
            } catch (Throwable unused) {
                z.c().getClass();
            }
            if (objInvoke instanceof String) {
                strF = (String) objInvoke;
            } else {
                int iMyPid = Process.myPid();
                Object systemService = context.getSystemService("activity");
                Intrinsics.e(systemService, "null cannot be cast to non-null type android.app.ActivityManager");
                List<ActivityManager.RunningAppProcessInfo> runningAppProcesses = ((ActivityManager) systemService).getRunningAppProcesses();
                if (runningAppProcesses != null) {
                    Iterator<T> it2 = runningAppProcesses.iterator();
                    while (true) {
                        if (!it2.hasNext()) {
                            next = null;
                            break;
                        }
                        next = it2.next();
                        if (((ActivityManager.RunningAppProcessInfo) next).pid == iMyPid) {
                            break;
                        }
                    }
                    ActivityManager.RunningAppProcessInfo runningAppProcessInfo = (ActivityManager.RunningAppProcessInfo) next;
                    if (runningAppProcessInfo != null) {
                        strF = runningAppProcessInfo.processName;
                    }
                }
            }
        }
        configuration.getClass();
        return Intrinsics.b(strF, context.getApplicationInfo().processName);
    }
}
