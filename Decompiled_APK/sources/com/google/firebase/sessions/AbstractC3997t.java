package com.google.firebase.sessions;

import android.app.ActivityManager;
import android.content.Context;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.firebase.sessions.t, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3997t {
    public static final C3998u a = new C3998u(0);
    public static final C3998u b = new C3998u(1);

    public static ArrayList a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        int i = context.getApplicationInfo().uid;
        String str = context.getApplicationInfo().processName;
        Object systemService = context.getSystemService("activity");
        ActivityManager activityManager = systemService instanceof ActivityManager ? (ActivityManager) systemService : null;
        List<ActivityManager.RunningAppProcessInfo> runningAppProcesses = activityManager != null ? activityManager.getRunningAppProcesses() : null;
        if (runningAppProcesses == null) {
            runningAppProcesses = kotlin.collections.K.a;
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
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            ActivityManager.RunningAppProcessInfo runningAppProcessInfo = (ActivityManager.RunningAppProcessInfo) it3.next();
            String str2 = runningAppProcessInfo.processName;
            Intrinsics.checkNotNullExpressionValue(str2, "runningAppProcessInfo.processName");
            arrayList2.add(new D(runningAppProcessInfo.pid, runningAppProcessInfo.importance, str2, Intrinsics.b(runningAppProcessInfo.processName, str)));
        }
        return arrayList2;
    }
}
