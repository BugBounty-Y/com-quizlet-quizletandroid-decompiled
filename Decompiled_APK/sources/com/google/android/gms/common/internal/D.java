package com.google.android.gms.common.internal;

import android.content.ComponentName;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import com.amazon.device.ads.DtbDeviceDataRetriever;

/* loaded from: classes2.dex */
public final class D implements Handler.Callback {
    public final /* synthetic */ E a;

    public /* synthetic */ D(E e) {
        this.a = e;
    }

    @Override // android.os.Handler.Callback
    public final boolean handleMessage(Message message) {
        int i = message.what;
        if (i == 0) {
            E e = this.a;
            synchronized (e.a) {
                try {
                    B b = (B) message.obj;
                    C c = (C) e.a.get(b);
                    if (c != null && c.a.isEmpty()) {
                        if (c.c) {
                            B b2 = c.e;
                            E e2 = c.g;
                            e2.c.removeMessages(1, b2);
                            e2.d.c(e2.b, c);
                            c.c = false;
                            c.b = 2;
                        }
                        e.a.remove(b);
                    }
                } finally {
                }
            }
            return true;
        }
        if (i != 1) {
            return false;
        }
        E e3 = this.a;
        synchronized (e3.a) {
            try {
                B b3 = (B) message.obj;
                C c2 = (C) e3.a.get(b3);
                if (c2 != null && c2.b == 3) {
                    String strValueOf = String.valueOf(b3);
                    StringBuilder sb = new StringBuilder(strValueOf.length() + 47);
                    sb.append("Timeout waiting for ServiceConnection callback ");
                    sb.append(strValueOf);
                    Log.e("GmsClientSupervisor", sb.toString(), new Exception());
                    ComponentName componentName = c2.f;
                    if (componentName == null) {
                        b3.getClass();
                        componentName = null;
                    }
                    if (componentName == null) {
                        String str = b3.b;
                        u.h(str);
                        componentName = new ComponentName(str, DtbDeviceDataRetriever.ORIENTATION_UNKNOWN);
                    }
                    c2.onServiceDisconnected(componentName);
                }
            } finally {
            }
        }
        return true;
    }
}
