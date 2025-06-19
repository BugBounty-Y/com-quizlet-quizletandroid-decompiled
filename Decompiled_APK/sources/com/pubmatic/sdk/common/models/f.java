package com.pubmatic.sdk.common.models;

import android.content.Context;
import android.location.Address;
import android.os.Build;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.util.DisplayMetrics;
import android.view.WindowManager;
import android.webkit.WebSettings;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.utility.o;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.TimeZone;

/* loaded from: classes2.dex */
public class f {
    private int b;
    private String c;
    private String f;
    private String g;
    private String h;
    private String i;
    private String j;
    private String k;
    private String l;
    private String n;

    @NonNull
    private final Context o;
    private float p;
    private String q;
    private String r;
    private String s;
    public int screenHeight;
    public int screenWidth;
    private final String a = "POBDeviceInfo";
    private String d = null;
    private Boolean e = null;
    private String m = null;

    public enum a {
        ANDROID_ID("3"),
        ADVERTISING_ID("9");

        private final String b;

        a(String str) {
            this.b = str;
        }

        public String getValue() {
            return this.b;
        }
    }

    public f(@NonNull Context context) throws NumberFormatException {
        this.f = null;
        this.l = null;
        this.o = context;
        updateAdvertisingIdInfo();
        this.c = a(context);
        TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService("phone");
        if (telephonyManager != null) {
            if (telephonyManager.getPhoneType() != 2) {
                String networkOperator = telephonyManager.getNetworkOperator();
                if (!TextUtils.isEmpty(networkOperator)) {
                    try {
                        this.q = "" + Integer.parseInt(networkOperator.substring(0, 3)) + "-" + Integer.parseInt(networkOperator.substring(3));
                    } catch (Exception unused) {
                        POBLog.error("POBDeviceInfo", "Unable to fetch MCC and MNC from %s", networkOperator);
                    }
                }
                String networkCountryIso = telephonyManager.getNetworkCountryIso();
                this.r = networkCountryIso != null ? networkCountryIso.toUpperCase(Locale.ENGLISH) : null;
            }
            a();
            this.f = telephonyManager.getNetworkOperatorName();
        }
        this.g = Locale.getDefault().getLanguage();
        this.h = Build.MANUFACTURER;
        this.i = Build.MODEL;
        this.j = "Android";
        this.k = Build.VERSION.RELEASE;
        DisplayMetrics displayMetrics = new DisplayMetrics();
        WindowManager windowManager = (WindowManager) context.getSystemService("window");
        if (windowManager != null) {
            windowManager.getDefaultDisplay().getMetrics(displayMetrics);
            this.screenWidth = displayMetrics.widthPixels;
            this.screenHeight = displayMetrics.heightPixels;
            this.l = displayMetrics.widthPixels + "x" + displayMetrics.heightPixels;
        }
        this.n = new SimpleDateFormat("ZZZZZ", Locale.getDefault()).format(Calendar.getInstance(TimeZone.getTimeZone("GMT"), Locale.getDefault()).getTime());
        this.p = this.o.getResources().getDisplayMetrics().density;
        this.b = o.getTimeOffsetInMinutes();
    }

    private String a(Context context) {
        String string = Settings.Secure.getString(context.getContentResolver(), "android_id");
        return string == null ? "" : string;
    }

    public String getAcceptLanguage() {
        return this.g;
    }

    public String getAdvertisingID() {
        return this.d;
    }

    public String getAndroidId() {
        return this.c;
    }

    public a getAndroidIdType(boolean z) {
        return z ? a.ADVERTISING_ID : a.ANDROID_ID;
    }

    public String getCarrierName() {
        return this.f;
    }

    public String getCurrentTime() {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Calendar.getInstance().getTime());
    }

    public String getCurrentTimeZone() {
        return this.n;
    }

    public String getISOAlpha2CountryCode() {
        return this.r;
    }

    public String getISOAlpha3CountryCode() {
        return this.s;
    }

    public Boolean getLmtEnabled() {
        return this.e;
    }

    public String getMake() {
        return this.h;
    }

    public String getMccmnc() {
        return this.q;
    }

    public String getModel() {
        return this.i;
    }

    public int getOrientation() {
        return this.o.getResources().getConfiguration().orientation;
    }

    public String getOsName() {
        return this.j;
    }

    public String getOsVersion() {
        return this.k;
    }

    public float getPxratio() {
        return this.p;
    }

    public int getScreenHeight() {
        return this.screenHeight;
    }

    public String getScreenResolution() {
        return this.l;
    }

    public int getScreenWidth() {
        return this.screenWidth;
    }

    public int getTimeZoneOffsetInMinutes() {
        return this.b;
    }

    public String getUserAgent() {
        String str = this.m;
        if (str != null) {
            return str;
        }
        try {
            String defaultUserAgent = WebSettings.getDefaultUserAgent(this.o);
            this.m = defaultUserAgent;
            return defaultUserAgent;
        } catch (Exception e) {
            POBLog.error("POBDeviceInfo", "Failed to retrieve user agent from web view, %s", e.getLocalizedMessage());
            try {
                String property = System.getProperty("http.agent");
                return property != null ? property : "";
            } catch (Exception e2) {
                POBLog.error("POBDeviceInfo", "Failed to retrieve user agent (using http.agent) from WebView, %s", e2.getLocalizedMessage());
                return "";
            }
        }
    }

    public void updateAdvertisingIdInfo() {
        com.pubmatic.sdk.common.utility.a aVar = com.pubmatic.sdk.common.utility.a.getInstance(this.o);
        aVar.updateAAID();
        String storedAdvertisingId = aVar.getStoredAdvertisingId();
        this.d = storedAdvertisingId;
        if (storedAdvertisingId != null) {
            this.e = Boolean.valueOf(aVar.getStoredLMTState());
        }
    }

    private void a() {
        Address address;
        String str = this.r;
        if (str != null) {
            this.s = a(str);
        }
        if (!TextUtils.isEmpty(this.s) || (address = new com.pubmatic.sdk.common.utility.g(this.o).getAddress()) == null) {
            return;
        }
        String countryCode = address.getCountryCode();
        if (TextUtils.isEmpty(countryCode)) {
            return;
        }
        this.s = a(countryCode);
    }

    private String a(@NonNull String str) {
        try {
            return new Locale(Locale.ENGLISH.getLanguage(), str).getISO3Country();
        } catch (MissingResourceException unused) {
            POBLog.warn("POBDeviceInfo", "Unable to get ISO 3 country code from ISO2 for input value as %s", str);
            return null;
        }
    }
}
