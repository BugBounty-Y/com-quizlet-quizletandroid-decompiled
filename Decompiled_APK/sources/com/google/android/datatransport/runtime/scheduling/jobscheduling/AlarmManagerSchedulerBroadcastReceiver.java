package com.google.android.datatransport.runtime.scheduling.jobscheduling;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Base64;
import androidx.camera.camera2.internal.RunnableC0131h;
import com.google.android.datatransport.runtime.q;

/* loaded from: classes2.dex */
public class AlarmManagerSchedulerBroadcastReceiver extends BroadcastReceiver {
    public static final /* synthetic */ int a = 0;

    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        String queryParameter = intent.getData().getQueryParameter("backendName");
        String queryParameter2 = intent.getData().getQueryParameter("extras");
        int iIntValue = Integer.valueOf(intent.getData().getQueryParameter("priority")).intValue();
        int i = intent.getExtras().getInt("attemptNumber");
        q.b(context);
        com.quizlet.data.repository.set.f fVarA = com.google.android.datatransport.runtime.i.a();
        fVarA.s(queryParameter);
        fVarA.d = com.google.android.datatransport.runtime.util.a.b(iIntValue);
        if (queryParameter2 != null) {
            fVarA.c = Base64.decode(queryParameter2, 0);
        }
        i iVar = q.a().d;
        com.google.android.datatransport.runtime.i iVarB = fVarA.b();
        RunnableC0131h runnableC0131h = new RunnableC0131h(19);
        iVar.getClass();
        iVar.e.execute(new e(i, 0, iVar, iVarB, runnableC0131h));
    }
}
