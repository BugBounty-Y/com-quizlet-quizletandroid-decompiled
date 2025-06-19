package com.google.android.gms.cloudmessaging;

import android.content.Context;
import android.os.Bundle;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;
import androidx.work.impl.model.v;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final /* synthetic */ class h implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ i b;

    public /* synthetic */ h(i iVar, int i) {
        this.a = i;
        this.b = iVar;
    }

    @Override // java.lang.Runnable
    public final void run() throws RemoteException {
        switch (this.a) {
            case 0:
                break;
            case 1:
                i iVar = this.b;
                synchronized (iVar) {
                    if (iVar.a == 1) {
                        iVar.a("Timed out while binding");
                    }
                }
                return;
            default:
                this.b.a("Service disconnected");
                return;
        }
        while (true) {
            i iVar2 = this.b;
            synchronized (iVar2) {
                try {
                    if (iVar2.a != 2) {
                        return;
                    }
                    if (iVar2.d.isEmpty()) {
                        iVar2.c();
                        return;
                    }
                    j jVar = (j) iVar2.d.poll();
                    iVar2.e.put(jVar.a, jVar);
                    ((ScheduledExecutorService) iVar2.f.d).schedule(new androidx.camera.core.impl.utils.futures.h(21, iVar2, jVar), 30L, TimeUnit.SECONDS);
                    if (Log.isLoggable("MessengerIpcClient", 3)) {
                        "Sending ".concat(String.valueOf(jVar));
                    }
                    k kVar = iVar2.f;
                    Messenger messenger = iVar2.b;
                    int i = jVar.c;
                    Context context = (Context) kVar.c;
                    Message messageObtain = Message.obtain();
                    messageObtain.what = i;
                    messageObtain.arg1 = jVar.a;
                    messageObtain.replyTo = messenger;
                    Bundle bundle = new Bundle();
                    bundle.putBoolean("oneWay", jVar.a());
                    bundle.putString("pkg", context.getPackageName());
                    bundle.putBundle("data", jVar.d);
                    messageObtain.setData(bundle);
                    try {
                        v vVar = iVar2.c;
                        Messenger messenger2 = (Messenger) vVar.b;
                        if (messenger2 != null) {
                            messenger2.send(messageObtain);
                        } else {
                            zzd zzdVar = (zzd) vVar.c;
                            if (zzdVar == null) {
                                throw new IllegalStateException("Both messengers are null");
                            }
                            Messenger messenger3 = zzdVar.a;
                            messenger3.getClass();
                            messenger3.send(messageObtain);
                        }
                    } catch (RemoteException e) {
                        iVar2.a(e.getMessage());
                    }
                } finally {
                }
            }
        }
    }
}
