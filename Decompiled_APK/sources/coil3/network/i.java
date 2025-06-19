package coil3.network;

import android.content.Context;
import android.net.ConnectivityManager;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;

/* loaded from: classes.dex */
public final /* synthetic */ class i extends C4956o implements Function1 {
    public static final i a = new i(1, g.class, "ConnectivityChecker", "ConnectivityChecker(Landroid/content/Context;)Lcoil3/network/ConnectivityChecker;", 1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Context applicationContext = ((Context) obj).getApplicationContext();
        ConnectivityManager connectivityManager = (ConnectivityManager) applicationContext.getSystemService(ConnectivityManager.class);
        d dVar = e.a;
        if (connectivityManager != null && androidx.core.content.c.a(applicationContext, "android.permission.ACCESS_NETWORK_STATE") == 0) {
            try {
                return new f(connectivityManager);
            } catch (Exception unused) {
            }
        }
        return dVar;
    }
}
