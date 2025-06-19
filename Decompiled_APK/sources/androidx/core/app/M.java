package androidx.core.app;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.os.DeadObjectException;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Message;
import android.os.RemoteException;
import android.util.Log;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/* loaded from: classes.dex */
public final class M implements Handler.Callback, ServiceConnection {
    public final Context a;
    public final Handler b;
    public final HashMap c = new HashMap();
    public Set d = new HashSet();

    public M(Context context) {
        this.a = context;
        HandlerThread handlerThread = new HandlerThread("NotificationManagerCompat");
        handlerThread.start();
        this.b = new Handler(handlerThread.getLooper(), this);
    }

    public final void a(L l) {
        boolean z;
        ArrayDeque arrayDeque;
        boolean zIsLoggable = Log.isLoggable("NotifManCompat", 3);
        ComponentName componentName = l.a;
        if (zIsLoggable) {
            Objects.toString(componentName);
            l.d.size();
        }
        if (l.d.isEmpty()) {
            return;
        }
        if (l.b) {
            z = true;
        } else {
            Intent component = new Intent(NotificationManagerCompat.ACTION_BIND_SIDE_CHANNEL).setComponent(componentName);
            Context context = this.a;
            boolean zBindService = context.bindService(component, this, 33);
            l.b = zBindService;
            if (zBindService) {
                l.e = 0;
            } else {
                Log.w("NotifManCompat", "Unable to bind to listener " + componentName);
                context.unbindService(this);
            }
            z = l.b;
        }
        if (!z || l.c == null) {
            b(l);
            return;
        }
        while (true) {
            arrayDeque = l.d;
            N n = (N) arrayDeque.peek();
            if (n == null) {
                break;
            }
            try {
                if (Log.isLoggable("NotifManCompat", 3)) {
                    n.toString();
                }
                ((J) n).a(l.c);
                arrayDeque.remove();
            } catch (DeadObjectException unused) {
                if (Log.isLoggable("NotifManCompat", 3)) {
                    Objects.toString(componentName);
                }
            } catch (RemoteException e) {
                Log.w("NotifManCompat", "RemoteException communicating with " + componentName, e);
            }
        }
        if (arrayDeque.isEmpty()) {
            return;
        }
        b(l);
    }

    public final void b(L l) {
        Handler handler = this.b;
        ComponentName componentName = l.a;
        if (handler.hasMessages(3, componentName)) {
            return;
        }
        int i = l.e + 1;
        l.e = i;
        if (i <= 6) {
            Log.isLoggable("NotifManCompat", 3);
            handler.sendMessageDelayed(handler.obtainMessage(3, componentName), (1 << r3) * 1000);
            return;
        }
        StringBuilder sb = new StringBuilder("Giving up on delivering ");
        ArrayDeque arrayDeque = l.d;
        sb.append(arrayDeque.size());
        sb.append(" tasks to ");
        sb.append(componentName);
        sb.append(" after ");
        sb.append(l.e);
        sb.append(" retries");
        Log.w("NotifManCompat", sb.toString());
        arrayDeque.clear();
    }

    @Override // android.os.Handler.Callback
    public final boolean handleMessage(Message message) {
        int i = message.what;
        HashMap map = this.c;
        android.support.v4.app.c cVar = null;
        Context context = this.a;
        if (i == 0) {
            N n = (N) message.obj;
            Set<String> enabledListenerPackages = NotificationManagerCompat.getEnabledListenerPackages(context);
            if (!enabledListenerPackages.equals(this.d)) {
                this.d = enabledListenerPackages;
                List<ResolveInfo> listQueryIntentServices = context.getPackageManager().queryIntentServices(new Intent().setAction(NotificationManagerCompat.ACTION_BIND_SIDE_CHANNEL), 0);
                HashSet hashSet = new HashSet();
                for (ResolveInfo resolveInfo : listQueryIntentServices) {
                    if (enabledListenerPackages.contains(resolveInfo.serviceInfo.packageName)) {
                        ServiceInfo serviceInfo = resolveInfo.serviceInfo;
                        ComponentName componentName = new ComponentName(serviceInfo.packageName, serviceInfo.name);
                        if (resolveInfo.serviceInfo.permission != null) {
                            Log.w("NotifManCompat", "Permission present on component " + componentName + ", not adding listener record.");
                        } else {
                            hashSet.add(componentName);
                        }
                    }
                }
                Iterator it2 = hashSet.iterator();
                while (it2.hasNext()) {
                    ComponentName componentName2 = (ComponentName) it2.next();
                    if (!map.containsKey(componentName2)) {
                        if (Log.isLoggable("NotifManCompat", 3)) {
                            Objects.toString(componentName2);
                        }
                        map.put(componentName2, new L(componentName2));
                    }
                }
                Iterator it3 = map.entrySet().iterator();
                while (it3.hasNext()) {
                    Map.Entry entry = (Map.Entry) it3.next();
                    if (!hashSet.contains(entry.getKey())) {
                        if (Log.isLoggable("NotifManCompat", 3)) {
                            Objects.toString(entry.getKey());
                        }
                        L l = (L) entry.getValue();
                        if (l.b) {
                            context.unbindService(this);
                            l.b = false;
                        }
                        l.c = null;
                        it3.remove();
                    }
                }
            }
            for (L l2 : map.values()) {
                l2.d.add(n);
                a(l2);
            }
        } else if (i == 1) {
            K k = (K) message.obj;
            L l3 = (L) map.get(k.a);
            if (l3 != null) {
                int i2 = android.support.v4.app.b.a;
                IBinder iBinder = k.b;
                if (iBinder != null) {
                    IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface(android.support.v4.app.c.P);
                    if (iInterfaceQueryLocalInterface == null || !(iInterfaceQueryLocalInterface instanceof android.support.v4.app.c)) {
                        android.support.v4.app.a aVar = new android.support.v4.app.a();
                        aVar.a = iBinder;
                        cVar = aVar;
                    } else {
                        cVar = (android.support.v4.app.c) iInterfaceQueryLocalInterface;
                    }
                }
                l3.c = cVar;
                l3.e = 0;
                a(l3);
                return true;
            }
        } else if (i == 2) {
            L l4 = (L) map.get((ComponentName) message.obj);
            if (l4 != null) {
                if (l4.b) {
                    context.unbindService(this);
                    l4.b = false;
                }
                l4.c = null;
                return true;
            }
        } else {
            if (i != 3) {
                return false;
            }
            L l5 = (L) map.get((ComponentName) message.obj);
            if (l5 != null) {
                a(l5);
                return true;
            }
        }
        return true;
    }

    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName componentName, IBinder iBinder) {
        if (Log.isLoggable("NotifManCompat", 3)) {
            Objects.toString(componentName);
        }
        this.b.obtainMessage(1, new K(componentName, iBinder)).sendToTarget();
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName componentName) {
        if (Log.isLoggable("NotifManCompat", 3)) {
            Objects.toString(componentName);
        }
        this.b.obtainMessage(2, componentName).sendToTarget();
    }
}
