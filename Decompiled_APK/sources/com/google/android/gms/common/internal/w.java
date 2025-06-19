package com.google.android.gms.common.internal;

import android.app.PendingIntent;
import android.os.Bundle;
import android.os.Looper;
import android.os.Message;
import android.util.Log;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.internal.ads.Ls;

/* loaded from: classes2.dex */
public final class w extends Ls {
    public final /* synthetic */ AbstractC1655e b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(AbstractC1655e abstractC1655e, Looper looper) {
        super(looper, 3);
        this.b = abstractC1655e;
    }

    @Override // android.os.Handler
    public final void handleMessage(Message message) {
        Boolean bool;
        p pVar;
        AbstractC1655e abstractC1655e = this.b;
        if (abstractC1655e.x.get() != message.arg1) {
            int i = message.what;
            if ((i == 2 || i == 1 || i == 7) && (pVar = (p) message.obj) != null) {
                synchronized (pVar) {
                    pVar.a = null;
                }
                AbstractC1655e abstractC1655e2 = pVar.c;
                synchronized (abstractC1655e2.l) {
                    abstractC1655e2.l.remove(pVar);
                }
                return;
            }
            return;
        }
        int i2 = message.what;
        if ((i2 == 1 || i2 == 7 || ((i2 == 4 && !(abstractC1655e instanceof com.google.android.gms.oss.licenses.d)) || i2 == 5)) && !abstractC1655e.r()) {
            p pVar2 = (p) message.obj;
            if (pVar2 != null) {
                synchronized (pVar2) {
                    pVar2.a = null;
                }
                AbstractC1655e abstractC1655e3 = pVar2.c;
                synchronized (abstractC1655e3.l) {
                    abstractC1655e3.l.remove(pVar2);
                }
                return;
            }
            return;
        }
        int i3 = message.what;
        if (i3 == 4) {
            abstractC1655e.u = new ConnectionResult(message.arg2);
            if (abstractC1655e.v() && !abstractC1655e.v) {
                abstractC1655e.w(3, null);
                return;
            }
            ConnectionResult connectionResult = abstractC1655e.u;
            if (connectionResult == null) {
                connectionResult = new ConnectionResult(8);
            }
            abstractC1655e.j.b(connectionResult);
            System.currentTimeMillis();
            return;
        }
        if (i3 == 5) {
            ConnectionResult connectionResult2 = abstractC1655e.u;
            if (connectionResult2 == null) {
                connectionResult2 = new ConnectionResult(8);
            }
            abstractC1655e.j.b(connectionResult2);
            System.currentTimeMillis();
            return;
        }
        if (i3 == 3) {
            Object obj = message.obj;
            abstractC1655e.j.b(new ConnectionResult(message.arg2, obj instanceof PendingIntent ? (PendingIntent) obj : null));
            System.currentTimeMillis();
            return;
        }
        if (i3 == 6) {
            abstractC1655e.w(5, null);
            InterfaceC1652b interfaceC1652b = abstractC1655e.o;
            if (interfaceC1652b != null) {
                interfaceC1652b.V(message.arg2);
            }
            System.currentTimeMillis();
            abstractC1655e.t(5, 1, null);
            return;
        }
        if (i3 == 2 && !abstractC1655e.q()) {
            p pVar3 = (p) message.obj;
            if (pVar3 != null) {
                synchronized (pVar3) {
                    pVar3.a = null;
                }
                AbstractC1655e abstractC1655e4 = pVar3.c;
                synchronized (abstractC1655e4.l) {
                    abstractC1655e4.l.remove(pVar3);
                }
                return;
            }
            return;
        }
        int i4 = message.what;
        if (i4 != 2 && i4 != 1 && i4 != 7) {
            StringBuilder sb = new StringBuilder(String.valueOf(i4).length() + 34);
            sb.append("Don't know how to handle message: ");
            sb.append(i4);
            Log.wtf("GmsClient", sb.toString(), new Exception());
            return;
        }
        p pVar4 = (p) message.obj;
        synchronized (pVar4) {
            try {
                bool = pVar4.a;
                if (pVar4.b) {
                    String string = pVar4.toString();
                    StringBuilder sb2 = new StringBuilder(string.length() + 47);
                    sb2.append("Callback proxy ");
                    sb2.append(string);
                    sb2.append(" being reused. This is not safe.");
                    Log.w("GmsClient", sb2.toString());
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (bool != null) {
            AbstractC1655e abstractC1655e5 = pVar4.f;
            int i5 = pVar4.d;
            if (i5 != 0) {
                abstractC1655e5.w(1, null);
                Bundle bundle = pVar4.e;
                pVar4.b(new ConnectionResult(i5, bundle != null ? (PendingIntent) bundle.getParcelable("pendingIntent") : null));
            } else if (!pVar4.a()) {
                abstractC1655e5.w(1, null);
                pVar4.b(new ConnectionResult(8, null));
            }
        }
        synchronized (pVar4) {
            pVar4.b = true;
        }
        synchronized (pVar4) {
            pVar4.a = null;
        }
        AbstractC1655e abstractC1655e6 = pVar4.c;
        synchronized (abstractC1655e6.l) {
            abstractC1655e6.l.remove(pVar4);
        }
    }
}
