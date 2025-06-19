package androidx.browser.customtabs;

import android.content.ComponentName;
import android.content.Context;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.IInterface;

/* loaded from: classes.dex */
public abstract class m implements ServiceConnection {
    public Context a;

    public abstract void a(ComponentName componentName, l lVar);

    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName componentName, IBinder iBinder) {
        android.support.customtabs.d dVar;
        if (this.a == null) {
            throw new IllegalStateException("Custom Tabs Service connected before an applicationcontext has been provided.");
        }
        int i = android.support.customtabs.c.a;
        if (iBinder == null) {
            dVar = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface(android.support.customtabs.d.O);
            if (iInterfaceQueryLocalInterface == null || !(iInterfaceQueryLocalInterface instanceof android.support.customtabs.d)) {
                android.support.customtabs.b bVar = new android.support.customtabs.b();
                bVar.a = iBinder;
                dVar = bVar;
            } else {
                dVar = (android.support.customtabs.d) iInterfaceQueryLocalInterface;
            }
        }
        a(componentName, new l(dVar, componentName));
    }
}
