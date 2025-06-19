package com.google.android.gms.common.api.internal;

import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.util.Log;
import com.google.android.gms.internal.ads.Ls;
import com.google.android.gms.internal.ads.RunnableC1782Ud;
import com.google.firebase.messaging.FirebaseMessaging;

/* loaded from: classes2.dex */
public final class q extends BroadcastReceiver {
    public final /* synthetic */ int a = 1;
    public Context b;
    public Object c;

    public /* synthetic */ q() {
    }

    public void a() {
        Log.isLoggable("FirebaseMessaging", 3);
        IntentFilter intentFilter = new IntentFilter("android.net.conn.CONNECTIVITY_CHANGE");
        RunnableC1782Ud runnableC1782Ud = (RunnableC1782Ud) this.c;
        if (runnableC1782Ud != null) {
            Context applicationContext = ((FirebaseMessaging) runnableC1782Ud.d).getApplicationContext();
            this.b = applicationContext;
            applicationContext.registerReceiver(this, intentFilter);
        }
    }

    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        switch (this.a) {
            case 0:
                Uri data = intent.getData();
                if ("com.google.android.gms".equals(data != null ? data.getSchemeSpecificPart() : null)) {
                    com.quizlet.data.repository.qclass.c cVar = (com.quizlet.data.repository.qclass.c) this.c;
                    l lVar = (l) ((com.google.common.util.concurrent.d) cVar.c).c;
                    lVar.c.set(null);
                    Ls ls = lVar.g.n;
                    ls.sendMessage(ls.obtainMessage(3));
                    AlertDialog alertDialog = (AlertDialog) cVar.b;
                    if (alertDialog.isShowing()) {
                        alertDialog.dismiss();
                    }
                    synchronized (this) {
                        try {
                            Context context2 = this.b;
                            if (context2 != null) {
                                context2.unregisterReceiver(this);
                            }
                            this.b = null;
                        } catch (Throwable th) {
                            throw th;
                        }
                    }
                    return;
                }
                return;
            default:
                RunnableC1782Ud runnableC1782Ud = (RunnableC1782Ud) this.c;
                if (runnableC1782Ud != null && runnableC1782Ud.a()) {
                    Log.isLoggable("FirebaseMessaging", 3);
                    RunnableC1782Ud runnableC1782Ud2 = (RunnableC1782Ud) this.c;
                    ((FirebaseMessaging) runnableC1782Ud2.d).enqueueTaskWithDelaySeconds(runnableC1782Ud2, 0L);
                    Context context3 = this.b;
                    if (context3 != null) {
                        context3.unregisterReceiver(this);
                    }
                    this.c = null;
                    return;
                }
                return;
        }
    }

    public q(com.quizlet.data.repository.qclass.c cVar) {
        this.c = cVar;
    }
}
