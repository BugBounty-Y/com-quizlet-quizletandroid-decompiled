package com.pubmatic.sdk.monitor;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.Application;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.graphics.Point;
import android.os.IBinder;
import android.os.RemoteException;
import android.provider.Settings;
import android.text.Html;
import android.text.TextUtils;
import android.view.ViewGroup;
import androidx.annotation.Keep;
import com.pubmatic.sdk.common.a;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.utility.o;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

@Keep
/* loaded from: classes2.dex */
public class POBMonitor {
    private static final String PACKAGE_NAME = "com.pubmatic.openwrapapp";
    private static final String SERVER_DOMAIN = "https://ads.pubmatic.com";
    private static final String SERVICE_ACTION = "com.pubmatic.openwrapapp.POBMonitorService";
    private static final String TAG = "POBMonitor";
    private static final String URL_PATH = "/openbidsdk/monitor/app.html";
    private static Application application;
    private static i monitorData;
    private static ServiceConnection serviceConnection;
    private com.pubmatic.sdk.webrendering.ui.h dialog;
    private com.pubmatic.sdk.monitor.d monitorUIDelegate;
    private com.pubmatic.sdk.monitor.e monitorView;
    private com.pubmatic.sdk.monitor.e previousMonitorView;
    private Point touchPointLocation;
    private com.pubmatic.sdk.monitor.g webView;

    public class a implements Runnable {
        @Override // java.lang.Runnable
        public void run() {
            POBMonitor.internalLoad();
        }
    }

    public class b implements Runnable {
        final /* synthetic */ i a;
        final /* synthetic */ String b;

        public b(i iVar, String str) {
            this.a = iVar;
            this.b = str;
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                new POBMonitor(this.a, null).init(this.b);
                POBLog.debug(POBMonitor.TAG, "Monitor console loaded successfully", new Object[0]);
            } catch (Exception e) {
                POBLog.debug(POBMonitor.TAG, e.getMessage(), new Object[0]);
            }
        }
    }

    public class c implements POBLog.POBLogging {
        public c() {
        }

        @Override // com.pubmatic.sdk.common.log.POBLog.POBLogging
        public void log(POBLog.POBLogMessage pOBLogMessage) throws JSONException {
            JSONObject logData = POBMonitor.getLogData(pOBLogMessage);
            JSONArray jSONArray = new JSONArray();
            jSONArray.put(logData);
            JSONObject jSONObject = new JSONObject();
            try {
                jSONObject.put("data", jSONArray);
            } catch (JSONException unused) {
                POBLog.warn(POBMonitor.TAG, "Not able to push data to js.", new Object[0]);
            }
            if (jSONObject.length() > 0) {
                o.runOnMainThread(new l(this, jSONObject));
            } else {
                POBLog.warn(POBMonitor.TAG, "Not able to push data to js.", new Object[0]);
            }
        }
    }

    public class d implements com.pubmatic.sdk.monitor.h {
        public d() {
        }

        @Override // com.pubmatic.sdk.monitor.h
        public void a() {
            if (POBMonitor.this.monitorUIDelegate.getCurrentActivity() != null) {
                POBMonitor pOBMonitor = POBMonitor.this;
                pOBMonitor.addButton(pOBMonitor.monitorUIDelegate.getCurrentActivity());
            }
        }

        @Override // com.pubmatic.sdk.monitor.h
        public void b() {
            POBMonitor.this.invalidateMonitorConsole();
        }
    }

    public class e implements com.pubmatic.sdk.monitor.c {
        public e() {
        }

        @Override // com.pubmatic.sdk.monitor.c
        public void a(Activity activity) {
            POBMonitor.this.invalidateMonitorConsole();
        }

        @Override // com.pubmatic.sdk.monitor.c
        public void onActivityPaused(Activity activity) {
            POBMonitor.this.clearPreviousMonitorView();
        }

        @Override // com.pubmatic.sdk.monitor.c
        public void onActivityResumed(Activity activity) {
            POBMonitor.this.addButton(activity);
        }
    }

    public class f implements com.pubmatic.sdk.monitor.f {
        final /* synthetic */ Activity a;

        public f(Activity activity) {
            this.a = activity;
        }

        @Override // com.pubmatic.sdk.monitor.f
        public void a() {
            POBMonitor.this.invalidateMonitorConsole();
        }

        @Override // com.pubmatic.sdk.monitor.f
        public void b() {
            POBMonitor.this.showDialog(this.a);
        }
    }

    public class g implements com.pubmatic.sdk.webrendering.ui.g {
        public g() {
        }

        @Override // com.pubmatic.sdk.webrendering.ui.g
        public void onClose() {
            ViewGroup viewGroup;
            if (POBMonitor.this.webView != null && (viewGroup = (ViewGroup) POBMonitor.this.webView.getParent()) != null) {
                viewGroup.removeView(POBMonitor.this.webView);
            }
            POBMonitor.this.dialog = null;
        }
    }

    public class h implements ServiceConnection {
        @Override // android.content.ServiceConnection
        public void onServiceConnected(ComponentName componentName, IBinder iBinder) {
            String monitorData;
            try {
                monitorData = com.pubmatic.sdk.monitor.a.asInterface(iBinder).getMonitorData();
            } catch (RemoteException e) {
                POBLog.debug(POBMonitor.TAG, e.getMessage(), new Object[0]);
                monitorData = null;
            }
            i unused = POBMonitor.monitorData = POBMonitor.process(monitorData);
            POBMonitor.loadMonitorModule();
        }

        @Override // android.content.ServiceConnection
        public void onServiceDisconnected(ComponentName componentName) {
        }
    }

    public static class i {
        private String a;
        private Integer b;
        private String c;

        private i() {
            this.a = "";
            this.b = 0;
        }

        public /* synthetic */ i(a aVar) {
            this();
        }
    }

    public /* synthetic */ POBMonitor(i iVar, a aVar) {
        this(iVar);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void addButton(Activity activity) {
        clearPreviousMonitorView();
        i iVar = monitorData;
        if (iVar == null || (iVar.b.intValue() & 1) != 0) {
            com.pubmatic.sdk.monitor.g gVar = this.webView;
            if (gVar == null || !gVar.isLoaded || activity == null) {
                POBLog.debug(TAG, "Not ready yet to attach touch Point", new Object[0]);
                return;
            }
            com.pubmatic.sdk.monitor.e eVar = new com.pubmatic.sdk.monitor.e(activity, this.touchPointLocation);
            this.monitorView = eVar;
            eVar.setListener(new f(activity));
            this.monitorView.bringToFront();
            this.previousMonitorView = this.monitorView;
            POBLog.debug(TAG, "Touch point attached", new Object[0]);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void clearPreviousMonitorView() {
        com.pubmatic.sdk.monitor.e eVar = this.previousMonitorView;
        if (eVar == null || eVar.getParent() == null) {
            this.touchPointLocation = new Point(0, 0);
            return;
        }
        this.touchPointLocation = this.previousMonitorView.getTouchPointLocation();
        ((ViewGroup) this.previousMonitorView.getParent()).removeView(this.previousMonitorView);
        this.previousMonitorView = null;
    }

    private static String encode(String str) throws UnsupportedEncodingException {
        return URLEncoder.encode(Html.escapeHtml(str), StandardCharsets.UTF_8.toString()).replaceAll("\\+", "%20").replaceAll("\\%21", "!").replaceAll("\\%27", "'").replaceAll("\\%28", "(").replaceAll("\\%29", ")").replaceAll("\\%7E", "~");
    }

    @SuppressLint({"PrivateApi"})
    private static Application getApplicationUsingReflection() {
        try {
            return (Application) Class.forName("android.app.ActivityThread").getMethod("currentApplication", null).invoke(null, null);
        } catch (ClassNotFoundException | IllegalAccessException | NoSuchMethodException | InvocationTargetException e2) {
            POBLog.debug(TAG, "Exception occurred while fetching the Application Instance. Message -> ", e2.getMessage());
            return null;
        }
    }

    private static i getFromBluetoothDeviceName() {
        try {
            String string = Settings.Secure.getString(application.getContentResolver(), "bluetooth_name");
            POBLog.verbose(TAG, "monitorKey: from Bluetooth - " + string, new Object[0]);
            return process(string);
        } catch (Exception e2) {
            POBLog.debug(TAG, "Exception occurs while fetching the bluetooth device name. " + e2.getMessage(), new Object[0]);
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static JSONObject getLogData(POBLog.POBLogMessage pOBLogMessage) throws JSONException {
        try {
            Field logField = getLogField(pOBLogMessage.getClass(), "mLogLevel");
            Field logField2 = getLogField(pOBLogMessage.getClass(), "mMsg");
            Field logField3 = getLogField(pOBLogMessage.getClass(), "mTAG");
            Field logField4 = getLogField(pOBLogMessage.getClass(), "PMSDK_TAG");
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("logLevel", logField.get(pOBLogMessage));
            jSONObject.put("message", encode((String) logField2.get(pOBLogMessage)));
            jSONObject.put("file", logField3.get(pOBLogMessage));
            jSONObject.put("sdk_tag", logField4.get(pOBLogMessage));
            jSONObject.put("line", "");
            jSONObject.put("function", "");
            return jSONObject;
        } catch (Exception e2) {
            POBLog.warn(TAG, e2.getMessage(), new Object[0]);
            return null;
        }
    }

    private static Field getLogField(Class<?> cls, String str) throws NoSuchFieldException, SecurityException {
        Field declaredField = cls.getDeclaredField(str);
        declaredField.setAccessible(true);
        return declaredField;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void init(String str) {
        com.pubmatic.sdk.monitor.g gVar = this.webView;
        if (gVar != null) {
            gVar.loadUrl(str);
        }
        POBLog.addLogger(logger());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void internalLoad() {
        Application applicationUsingReflection = getApplicationUsingReflection();
        if (applicationUsingReflection != null) {
            application = applicationUsingReflection;
            if (monitorData == null) {
                monitorData = getFromBluetoothDeviceName();
            }
            if (monitorData == null) {
                registerToolAppService();
            } else {
                loadMonitorModule();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void invalidateMonitorConsole() {
        com.pubmatic.sdk.webrendering.ui.h hVar = this.dialog;
        if (hVar != null) {
            hVar.dismiss();
            this.dialog = null;
        }
        clearPreviousMonitorView();
        this.monitorView = null;
        this.monitorUIDelegate.reset();
        serviceConnection = null;
    }

    public static void load() {
        o.runOnBackgroundThread(new a());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void loadMonitorModule() {
        try {
            i iVar = monitorData;
            if (iVar != null) {
                String str = iVar.c;
                String str2 = String.format("%s?plugins=%d&pubId=%s&bundleId=%s&ifa=%s", str != null ? str.concat(URL_PATH) : "https://ads.pubmatic.com/openbidsdk/monitor/app.html", monitorData.b, monitorData.a, application.getPackageName(), Settings.Secure.getString(application.getContentResolver(), "android_id"));
                com.pubmatic.sdk.common.a.setLogLevel(a.EnumC0007a.All);
                o.runOnMainThread(new b(monitorData, str2));
            }
        } catch (Exception e2) {
            POBLog.debug(TAG, e2.getMessage(), new Object[0]);
        }
    }

    private POBLog.POBLogging logger() {
        return new c();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static i process(String str) {
        String strReplaceAll;
        a aVar = null;
        if (!TextUtils.isEmpty(str) && (strReplaceAll = str.replaceAll("\"", "")) != null && strReplaceAll.startsWith("OB")) {
            String[] strArrSplit = strReplaceAll.replace("OB", "").split("_");
            if (strArrSplit.length != 0) {
                try {
                    i iVar = new i(aVar);
                    iVar.a = strArrSplit[0];
                    if (strArrSplit.length > 1) {
                        iVar.b = Integer.valueOf(Integer.parseInt(strArrSplit[1]));
                    }
                    if (strArrSplit.length > 2) {
                        iVar.c = strArrSplit[2];
                    }
                    return iVar;
                } catch (Exception e2) {
                    POBLog.debug(TAG, e2.getMessage(), new Object[0]);
                }
            }
        }
        return null;
    }

    private static void registerToolAppService() {
        serviceConnection = new h();
        try {
            Intent intent = new Intent(SERVICE_ACTION);
            intent.setPackage(PACKAGE_NAME);
            application.bindService(intent, serviceConnection, 1);
        } catch (Exception e2) {
            POBLog.debug(TAG, e2.getMessage(), new Object[0]);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showDialog(Activity activity) {
        if (this.dialog == null && this.webView != null) {
            this.dialog = new com.pubmatic.sdk.webrendering.ui.h(activity, this.webView, new g());
        }
        com.pubmatic.sdk.webrendering.ui.h hVar = this.dialog;
        if (hVar != null) {
            hVar.show();
        }
    }

    private POBMonitor(i iVar) {
        this.touchPointLocation = new Point(0, 0);
        monitorData = iVar;
        try {
            com.pubmatic.sdk.monitor.g gVar = new com.pubmatic.sdk.monitor.g(application.getApplicationContext());
            this.webView = gVar;
            gVar.initWebView(new d());
            com.pubmatic.sdk.monitor.d dVar = new com.pubmatic.sdk.monitor.d(application);
            this.monitorUIDelegate = dVar;
            dVar.start(new e());
        } catch (Exception unused) {
            POBLog.error(TAG, "Unable to instantiate Web View", new Object[0]);
            invalidateMonitorConsole();
        }
    }
}
