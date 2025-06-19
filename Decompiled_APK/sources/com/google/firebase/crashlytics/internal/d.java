package com.google.firebase.crashlytics.internal;

import android.app.ActivityManager;
import android.app.Application;
import android.content.Context;
import android.os.Build;
import android.os.Process;
import com.google.firebase.crashlytics.internal.model.C3925a0;
import com.google.firebase.crashlytics.internal.model.D0;
import com.google.firebase.crashlytics.internal.model.Z;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d {
    public static final d a = new d();

    public static C3925a0 a(d dVar, String processName, int i, int i2, int i3) {
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        dVar.getClass();
        Intrinsics.checkNotNullParameter(processName, "processName");
        Z z = new Z();
        if (processName == null) {
            throw new NullPointerException("Null processName");
        }
        z.a = processName;
        z.b = i;
        byte b = (byte) (z.e | 1);
        z.c = i2;
        z.d = false;
        z.e = (byte) (((byte) (b | 2)) | 4);
        C3925a0 c3925a0A = z.a();
        Intrinsics.checkNotNullExpressionValue(c3925a0A, "builder()\n      .setProc…ltProcess)\n      .build()");
        return c3925a0A;
    }

    public static ArrayList b(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        int i = context.getApplicationInfo().uid;
        String str = context.getApplicationInfo().processName;
        Object systemService = context.getSystemService("activity");
        ActivityManager activityManager = systemService instanceof ActivityManager ? (ActivityManager) systemService : null;
        List<ActivityManager.RunningAppProcessInfo> runningAppProcesses = activityManager != null ? activityManager.getRunningAppProcesses() : null;
        if (runningAppProcesses == null) {
            runningAppProcesses = K.a;
        }
        ArrayList arrayListJ = CollectionsKt.J(runningAppProcesses);
        ArrayList arrayList = new ArrayList();
        Iterator it2 = arrayListJ.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            if (((ActivityManager.RunningAppProcessInfo) next).uid == i) {
                arrayList.add(next);
            }
        }
        ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            ActivityManager.RunningAppProcessInfo runningAppProcessInfo = (ActivityManager.RunningAppProcessInfo) it3.next();
            Z z = new Z();
            String str2 = runningAppProcessInfo.processName;
            if (str2 == null) {
                throw new NullPointerException("Null processName");
            }
            z.a = str2;
            z.b = runningAppProcessInfo.pid;
            byte b = (byte) (z.e | 1);
            z.c = runningAppProcessInfo.importance;
            z.e = (byte) (b | 2);
            z.d = Intrinsics.b(str2, str);
            z.e = (byte) (z.e | 4);
            arrayList2.add(z.a());
        }
        return arrayList2;
    }

    public D0 c(Context context) {
        Object next;
        String processName;
        Intrinsics.checkNotNullParameter(context, "context");
        int iMyPid = Process.myPid();
        Iterator it2 = b(context).iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            if (((C3925a0) ((D0) next)).b == iMyPid) {
                break;
            }
        }
        D0 d0 = (D0) next;
        if (d0 != null) {
            return d0;
        }
        int i = Build.VERSION.SDK_INT;
        if (i > 33) {
            processName = Process.myProcessName();
            Intrinsics.checkNotNullExpressionValue(processName, "{\n      Process.myProcessName()\n    }");
        } else if (i < 28 || (processName = Application.getProcessName()) == null) {
            processName = "";
        }
        return a(this, processName, iMyPid, 0, 12);
    }
}
