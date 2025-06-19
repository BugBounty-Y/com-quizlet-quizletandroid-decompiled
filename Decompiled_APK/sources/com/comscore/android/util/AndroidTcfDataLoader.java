package com.comscore.android.util;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import com.comscore.util.TcfDataLoader;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes.dex */
public class AndroidTcfDataLoader implements TcfDataLoader, SharedPreferences.OnSharedPreferenceChangeListener {
    public static final int COMSCORE_VENDOR_INDEX = 77;
    public static final String IABTCF_CMP_SDK_ID = "IABTCF_CmpSdkID";
    public static final String IABTCF_GDPR_APPLIES = "IABTCF_gdprApplies";
    public static final String IABTCF_PUBLISHER_CC = "IABTCF_PublisherCC";
    public static final String IABTCF_PURPOSE_CONSENTS = "IABTCF_PurposeConsents";
    public static final String IABTCF_PURPOSE_ONE_TREATMENT = "IABTCF_PurposeOneTreatment";
    public static final String IABTCF_VENDOR_CONSENTS = "IABTCF_VendorConsents";
    public static final String IABTCF_VENDOR_LEGITIMATE_INTERESTS = "IABTCF_VendorLegitimateInterests";
    protected boolean _enabled;
    protected boolean _registered;
    private Map<Integer, Boolean> a;
    private boolean b;
    private boolean c;
    private boolean d;
    private boolean e;
    private boolean f;
    private String g;
    private SharedPreferences h;

    public AndroidTcfDataLoader() {
        HashMap map = new HashMap();
        this.a = map;
        Boolean bool = Boolean.FALSE;
        map.put(1, bool);
        this.a.put(7, bool);
        this.a.put(8, bool);
        this.a.put(9, bool);
        this.a.put(10, bool);
        this._enabled = false;
    }

    private void a() {
        SharedPreferences sharedPreferences;
        if (this._registered || (sharedPreferences = this.h) == null) {
            return;
        }
        g(sharedPreferences);
        this.h.registerOnSharedPreferenceChangeListener(this);
        this._registered = true;
    }

    private void b() {
        SharedPreferences sharedPreferences;
        if (!this._registered || (sharedPreferences = this.h) == null) {
            return;
        }
        sharedPreferences.unregisterOnSharedPreferenceChangeListener(this);
        this._registered = false;
    }

    private void c(SharedPreferences sharedPreferences) {
        this.c = sharedPreferences.getInt("IABTCF_gdprApplies", 0) == 1;
    }

    private void d(SharedPreferences sharedPreferences) {
        String string = sharedPreferences.getString("IABTCF_VendorLegitimateInterests", "");
        if (string.length() >= 76) {
            this.e = string.charAt(76) == '1';
        }
    }

    private void e(SharedPreferences sharedPreferences) {
        this.g = sharedPreferences.getString("IABTCF_PublisherCC", "AA");
    }

    private void f(SharedPreferences sharedPreferences) {
        this.f = sharedPreferences.getInt("IABTCF_PurposeOneTreatment", 0) == 1;
    }

    private void g(SharedPreferences sharedPreferences) {
        a(sharedPreferences);
        c(sharedPreferences);
        h(sharedPreferences);
        d(sharedPreferences);
        b(sharedPreferences);
        e(sharedPreferences);
        f(sharedPreferences);
    }

    private void h(SharedPreferences sharedPreferences) {
        String string = sharedPreferences.getString("IABTCF_VendorConsents", "");
        if (string.length() >= 77) {
            this.d = string.charAt(76) == '1';
        }
    }

    @Override // com.comscore.util.TcfDataLoader
    public Map<Integer, Boolean> getConsents() {
        return this.a;
    }

    @Override // com.comscore.util.TcfDataLoader
    public String getPublisherCountryCode() {
        return this.g;
    }

    @Override // com.comscore.util.TcfDataLoader
    public boolean isCmpPresent() {
        return this.b;
    }

    @Override // com.comscore.util.TcfDataLoader
    public boolean isCmpReady() {
        return true;
    }

    @Override // com.comscore.util.TcfDataLoader
    public boolean isGdprApplicable() {
        return this.c;
    }

    @Override // com.comscore.util.TcfDataLoader
    public boolean isLegitimateInterestConsent() {
        return this.e;
    }

    @Override // com.comscore.util.TcfDataLoader
    public boolean isPurposeOneTreatmentEnabled() {
        return this.f;
    }

    @Override // com.comscore.util.TcfDataLoader
    public boolean isServiceSpecificEnabled() {
        return true;
    }

    @Override // com.comscore.util.TcfDataLoader
    public boolean isVendorConsentEnabled() {
        return this.d;
    }

    @Override // android.content.SharedPreferences.OnSharedPreferenceChangeListener
    public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String str) {
        if ("IABTCF_CmpSdkID".equals(str)) {
            a(sharedPreferences);
            return;
        }
        if ("IABTCF_gdprApplies".equals(str)) {
            c(sharedPreferences);
            return;
        }
        if ("IABTCF_VendorConsents".equals(str)) {
            h(sharedPreferences);
            return;
        }
        if ("IABTCF_VendorLegitimateInterests".equals(str)) {
            d(sharedPreferences);
            return;
        }
        if ("IABTCF_PurposeConsents".equals(str)) {
            b(sharedPreferences);
        } else if ("IABTCF_PublisherCC".equals(str)) {
            e(sharedPreferences);
        } else if ("IABTCF_PurposeOneTreatment".equals(str)) {
            f(sharedPreferences);
        }
    }

    public void setContext(Context context) {
        if (this.h != null) {
            return;
        }
        this.h = PreferenceManager.getDefaultSharedPreferences(context);
        if (this._enabled) {
            a();
        }
    }

    @Override // com.comscore.util.TcfDataLoader
    public void setEnabled(boolean z) {
        if (this._enabled == z) {
            return;
        }
        this._enabled = z;
        if (z) {
            a();
        } else {
            b();
        }
    }

    private void b(SharedPreferences sharedPreferences) {
        String string = sharedPreferences.getString("IABTCF_PurposeConsents", null);
        if (string == null || string.length() < 10) {
            return;
        }
        this.a.put(1, Boolean.valueOf(string.charAt(0) == '1'));
        this.a.put(7, Boolean.valueOf(string.charAt(6) == '1'));
        this.a.put(8, Boolean.valueOf(string.charAt(7) == '1'));
        this.a.put(9, Boolean.valueOf(string.charAt(8) == '1'));
        this.a.put(10, Boolean.valueOf(string.charAt(9) == '1'));
    }

    private void a(SharedPreferences sharedPreferences) {
        this.b = sharedPreferences.contains("IABTCF_CmpSdkID");
    }
}
