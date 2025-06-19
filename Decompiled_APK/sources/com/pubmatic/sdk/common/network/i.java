package com.pubmatic.sdk.common.network;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkInfo;
import android.os.Build;
import android.telephony.PhoneStateListener;
import android.telephony.TelephonyCallback;
import android.telephony.TelephonyDisplayInfo;
import android.telephony.TelephonyManager;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/* loaded from: classes2.dex */
public class i {

    @NonNull
    private final Context a;
    private final ConnectivityManager c;
    protected List<j> connectivityListeners;

    @NonNull
    private a b = a.UNKNOWN;
    private f d = null;

    public enum a {
        UNKNOWN(0),
        ETHERNET(1),
        WIFI(2),
        CELLULAR_NETWORK_UN(3),
        CELLULAR_NETWORK_2G(4),
        CELLULAR_NETWORK_3G(5),
        CELLULAR_NETWORK_4G(6),
        CELLULAR_NETWORK_5G(7);

        private final int b;

        a(int i) {
            this.b = i;
        }

        public int getValue() {
            return this.b;
        }
    }

    public class b extends ConnectivityManager.NetworkCallback {
        public b() {
        }

        @Override // android.net.ConnectivityManager.NetworkCallback
        public void onAvailable(@NonNull Network network) {
            i.this.a();
        }

        @Override // android.net.ConnectivityManager.NetworkCallback
        public void onLost(@NonNull Network network) {
            i.this.a();
        }
    }

    public class c implements k {
        final /* synthetic */ TelephonyManager a;

        public c(TelephonyManager telephonyManager) {
            this.a = telephonyManager;
        }

        @Override // com.pubmatic.sdk.common.network.k
        public void a(TelephonyDisplayInfo telephonyDisplayInfo) {
            i iVar = i.this;
            iVar.b = iVar.a(telephonyDisplayInfo);
            if (i.this.d != null) {
                this.a.unregisterTelephonyCallback(i.this.d);
            }
        }
    }

    public class d extends PhoneStateListener {
        final /* synthetic */ TelephonyManager a;

        public d(TelephonyManager telephonyManager) {
            this.a = telephonyManager;
        }

        @Override // android.telephony.PhoneStateListener
        public void onDisplayInfoChanged(@NonNull TelephonyDisplayInfo telephonyDisplayInfo) {
            super.onDisplayInfoChanged(telephonyDisplayInfo);
            i iVar = i.this;
            iVar.b = iVar.a(telephonyDisplayInfo);
            this.a.listen(this, 0);
        }
    }

    public class e implements Runnable {
        public e() {
        }

        @Override // java.lang.Runnable
        public void run() {
            i.this.b();
        }
    }

    public static class f extends TelephonyCallback implements TelephonyCallback.DisplayInfoListener {

        @NonNull
        private final k a;

        public f(@NonNull k kVar) {
            this.a = kVar;
        }

        public void onDisplayInfoChanged(@NonNull TelephonyDisplayInfo telephonyDisplayInfo) {
            this.a.a(telephonyDisplayInfo);
        }
    }

    public i(@NonNull Context context) {
        Context applicationContext = context.getApplicationContext();
        this.a = applicationContext;
        this.c = (ConnectivityManager) applicationContext.getSystemService("connectivity");
        c();
        updateConnectionType();
    }

    private void d() {
        TelephonyManager telephonyManager = (TelephonyManager) this.a.getSystemService("phone");
        if (telephonyManager == null) {
            this.b = a.CELLULAR_NETWORK_UN;
        } else if (Build.VERSION.SDK_INT >= 30) {
            a(telephonyManager);
        } else {
            this.b = a(telephonyManager.getNetworkType());
        }
    }

    @NonNull
    public a getConnectionType() {
        return this.b;
    }

    public boolean isNetworkAvailable() {
        return isNetworkAvailable(this.a);
    }

    public boolean isWiFiConnected() {
        return this.b == a.WIFI;
    }

    public void registerConnectivityListener(j jVar) {
        if (this.connectivityListeners == null) {
            this.connectivityListeners = new ArrayList(1);
        }
        this.connectivityListeners.add(jVar);
    }

    public void resetConnectivityListener() {
        List<j> list = this.connectivityListeners;
        if (list != null) {
            list.clear();
            this.connectivityListeners = null;
        }
    }

    public void unregisterConnectivityListener(j jVar) {
        List<j> list;
        if (jVar == null || (list = this.connectivityListeners) == null || !list.contains(jVar)) {
            return;
        }
        this.connectivityListeners.remove(jVar);
        if (this.connectivityListeners.size() == 0) {
            this.connectivityListeners = null;
        }
    }

    public void updateConnectionType() {
        if (this.c == null || !com.pubmatic.sdk.common.utility.o.hasPermission(this.a, "android.permission.ACCESS_NETWORK_STATE")) {
            this.b = a.UNKNOWN;
            return;
        }
        NetworkInfo activeNetworkInfo = this.c.getActiveNetworkInfo();
        if (activeNetworkInfo == null) {
            this.b = a.UNKNOWN;
            return;
        }
        int type = activeNetworkInfo.getType();
        if (type == 0) {
            d();
        } else if (type == 1) {
            this.b = a.WIFI;
        } else {
            if (type != 9) {
                return;
            }
            this.b = a.ETHERNET;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void b() {
        updateConnectionType();
        if (this.connectivityListeners != null) {
            for (int i = 0; i < this.connectivityListeners.size(); i++) {
                j jVar = this.connectivityListeners.get(i);
                if (jVar != null) {
                    jVar.onNetworkConnectionChanged(isNetworkAvailable(this.a));
                }
            }
        }
    }

    private void c() {
        ConnectivityManager connectivityManager = this.c;
        if (connectivityManager != null) {
            connectivityManager.registerDefaultNetworkCallback(new b());
        }
    }

    public static boolean isNetworkAvailable(Context context) {
        NetworkInfo activeNetworkInfo;
        ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService("connectivity");
        return connectivityManager != null && com.pubmatic.sdk.common.utility.o.hasPermission(context, "android.permission.ACCESS_NETWORK_STATE") && (activeNetworkInfo = connectivityManager.getActiveNetworkInfo()) != null && activeNetworkInfo.isConnectedOrConnecting();
    }

    private void a(@NonNull TelephonyManager telephonyManager) {
        if (com.pubmatic.sdk.common.utility.o.hasPermission(this.a, "android.permission.READ_PHONE_STATE")) {
            try {
                if (Build.VERSION.SDK_INT >= 31) {
                    ExecutorService executorServiceNewSingleThreadExecutor = Executors.newSingleThreadExecutor();
                    f fVar = new f(new c(telephonyManager));
                    this.d = fVar;
                    telephonyManager.registerTelephonyCallback(executorServiceNewSingleThreadExecutor, fVar);
                    return;
                }
                telephonyManager.listen(new d(telephonyManager), 1048576);
                return;
            } catch (IllegalStateException e2) {
                e = e2;
                this.b = a.CELLULAR_NETWORK_UN;
                POBLog.warn("POBNetworkMonitor", "Not able fetch connection type due to " + e.getMessage(), new Object[0]);
                return;
            } catch (SecurityException e3) {
                e = e3;
                this.b = a.CELLULAR_NETWORK_UN;
                POBLog.warn("POBNetworkMonitor", "Not able fetch connection type due to " + e.getMessage(), new Object[0]);
                return;
            }
        }
        this.b = a.CELLULAR_NETWORK_UN;
        POBLog.warn("POBNetworkMonitor", "Not able fetch connection type due to android.permission.READ_PHONE_STATE permission is not available for the app!", new Object[0]);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public a a(@NonNull TelephonyDisplayInfo telephonyDisplayInfo) {
        if (telephonyDisplayInfo.getOverrideNetworkType() != 2 && telephonyDisplayInfo.getOverrideNetworkType() != 3 && telephonyDisplayInfo.getOverrideNetworkType() != 5) {
            return a(telephonyDisplayInfo.getNetworkType());
        }
        return a.CELLULAR_NETWORK_5G;
    }

    private a a(int i) {
        if (i != 20) {
            switch (i) {
                case 1:
                case 2:
                case 4:
                case 7:
                case 11:
                    return a.CELLULAR_NETWORK_2G;
                case 3:
                case 5:
                case 6:
                case 8:
                case 9:
                case 10:
                case 12:
                case 14:
                case 15:
                    return a.CELLULAR_NETWORK_3G;
                case 13:
                    return a.CELLULAR_NETWORK_4G;
                default:
                    return a.CELLULAR_NETWORK_UN;
            }
        }
        return a.CELLULAR_NETWORK_5G;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a() {
        com.pubmatic.sdk.common.utility.o.runOnMainThread(new e());
    }
}
