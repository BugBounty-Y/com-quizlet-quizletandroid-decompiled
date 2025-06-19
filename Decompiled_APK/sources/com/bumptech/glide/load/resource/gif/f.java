package com.bumptech.glide.load.resource.gif;

import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import com.google.android.gms.cloudmessaging.j;
import com.google.android.gms.cloudmessaging.zzt;

/* loaded from: classes.dex */
public final class f implements Handler.Callback {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ f(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.os.Handler.Callback
    public final boolean handleMessage(Message message) {
        switch (this.a) {
            case 0:
                int i = message.what;
                g gVar = (g) this.b;
                if (i == 1) {
                    gVar.b((d) message.obj);
                    return true;
                }
                if (i == 2) {
                    gVar.d.i((d) message.obj);
                }
                return false;
            case 1:
                int i2 = message.arg1;
                Log.isLoggable("MessengerIpcClient", 3);
                com.google.android.gms.cloudmessaging.i iVar = (com.google.android.gms.cloudmessaging.i) this.b;
                synchronized (iVar) {
                    try {
                        j jVar = (j) iVar.e.get(i2);
                        if (jVar == null) {
                            Log.w("MessengerIpcClient", "Received response for unknown request: " + i2);
                            return true;
                        }
                        iVar.e.remove(i2);
                        iVar.c();
                        Bundle data = message.getData();
                        if (data.getBoolean("unsupported", false)) {
                            jVar.b(new zzt("Not supported by GmsCore", null));
                            return true;
                        }
                        switch (jVar.e) {
                            case 0:
                                if (!data.getBoolean("ack", false)) {
                                    jVar.b(new zzt("Invalid response to one way request", null));
                                    return true;
                                }
                                if (Log.isLoggable("MessengerIpcClient", 3)) {
                                    jVar.toString();
                                }
                                jVar.b.b(null);
                                return true;
                            default:
                                Bundle bundle = data.getBundle("data");
                                if (bundle == null) {
                                    bundle = Bundle.EMPTY;
                                }
                                if (Log.isLoggable("MessengerIpcClient", 3)) {
                                    jVar.toString();
                                    String.valueOf(bundle);
                                }
                                jVar.b.b(bundle);
                                return true;
                        }
                    } finally {
                    }
                }
            default:
                if (message.what != 0) {
                    return false;
                }
                com.quizlet.data.repository.achievements.h hVar = (com.quizlet.data.repository.achievements.h) this.b;
                com.google.android.material.snackbar.i iVar2 = (com.google.android.material.snackbar.i) message.obj;
                synchronized (hVar.a) {
                    if (((com.google.android.material.snackbar.i) hVar.c) == iVar2 || ((com.google.android.material.snackbar.i) hVar.d) == iVar2) {
                        hVar.a(iVar2, 2);
                    }
                }
                return true;
        }
    }
}
