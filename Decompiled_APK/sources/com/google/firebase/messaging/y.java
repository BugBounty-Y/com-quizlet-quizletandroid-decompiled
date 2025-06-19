package com.google.firebase.messaging;

import android.content.SharedPreferences;
import android.text.TextUtils;
import java.lang.ref.WeakReference;
import java.util.ArrayDeque;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public final class y {
    public static WeakReference c;
    public com.quizlet.remote.model.notes.e a;
    public final ScheduledThreadPoolExecutor b;

    public y(SharedPreferences sharedPreferences, ScheduledThreadPoolExecutor scheduledThreadPoolExecutor) {
        this.b = scheduledThreadPoolExecutor;
    }

    public final synchronized x a() {
        String str;
        x xVar;
        com.quizlet.remote.model.notes.e eVar = this.a;
        synchronized (((ArrayDeque) eVar.e)) {
            str = (String) ((ArrayDeque) eVar.e).peek();
        }
        Pattern pattern = x.d;
        xVar = null;
        if (!TextUtils.isEmpty(str)) {
            String[] strArrSplit = str.split("!", -1);
            if (strArrSplit.length == 2) {
                xVar = new x(strArrSplit[0], strArrSplit[1]);
            }
        }
        return xVar;
    }
}
