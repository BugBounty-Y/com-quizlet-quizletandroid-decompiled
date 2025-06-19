package com.pubmatic.sdk.common;

import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.utility.o;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public class j {
    private Boolean d;
    private com.pubmatic.sdk.common.models.h e;
    private com.pubmatic.sdk.common.models.k h;
    private com.pubmatic.sdk.common.models.d i;
    private boolean a = true;
    private long b = 600000;
    private boolean c = false;
    private boolean f = true;
    private boolean g = true;

    @NonNull
    private final Map<String, List<com.pubmatic.sdk.common.models.g>> j = Collections.synchronizedMap(new HashMap());

    public void addExternalUserId(@NonNull com.pubmatic.sdk.common.models.g gVar) {
        if (gVar == null || o.isNullOrEmpty(gVar.getId()) || o.isNullOrEmpty(gVar.getSource())) {
            POBLog.warn("POBSDKConfig", "%s is null or required fields are not available", "External User Id");
            return;
        }
        String source = gVar.getSource();
        if (!this.j.containsKey(source)) {
            ArrayList arrayList = new ArrayList();
            arrayList.add(gVar);
            this.j.put(source, arrayList);
            return;
        }
        List<com.pubmatic.sdk.common.models.g> list = this.j.get(source);
        if (list != null) {
            for (com.pubmatic.sdk.common.models.g gVar2 : list) {
                if (gVar2 != null && gVar2.getId().equals(gVar.getId())) {
                    POBLog.warn("POBSDKConfig", "%s with duplicate %s not allowed", "External User Id", "partner Id");
                    return;
                }
            }
            list.add(gVar);
            this.j.put(source, list);
        }
    }

    public void allowAdvertisingId(boolean z) {
        this.g = z;
    }

    public void allowLocationAccess(boolean z) {
        this.a = z;
    }

    public com.pubmatic.sdk.common.models.d getApplicationInfo() {
        return this.i;
    }

    @NonNull
    public Map<String, List<com.pubmatic.sdk.common.models.g>> getExternalUserIds() {
        return this.j;
    }

    public com.pubmatic.sdk.common.models.h getLocation() {
        return this.e;
    }

    public long getLocationDetectionDurationInMillis() {
        return this.b;
    }

    public <T> T getMeasurementProvider(@NonNull String str) {
        try {
            return (T) Class.forName(str).getConstructor(null).newInstance(null);
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException | NoSuchMethodException | SecurityException | InvocationTargetException e) {
            POBLog.error(com.pubmatic.sdk.omsdk.d.TAG, "%s", e.getMessage());
            return null;
        }
    }

    public com.pubmatic.sdk.common.models.k getUserInfo() {
        return this.h;
    }

    public boolean isAllowAdvertisingId() {
        return this.g;
    }

    public Boolean isCoppa() {
        return this.d;
    }

    public boolean isLocationAccessAllowed() {
        return this.a;
    }

    public boolean isRequestSecureCreative() {
        return this.f;
    }

    public boolean isUseInternalBrowser() {
        return this.c;
    }

    public void removeAllExternalUserIds() {
        this.j.clear();
    }

    public void removeExternalUserIds(@NonNull String str) {
        if (str != null) {
            this.j.remove(str);
        }
    }

    public void setApplicationInfo(com.pubmatic.sdk.common.models.d dVar) {
        this.i = dVar;
    }

    public void setCoppa(boolean z) {
        this.d = Boolean.valueOf(z);
    }

    public void setLocation(com.pubmatic.sdk.common.models.h hVar) {
        this.e = hVar;
    }

    public void setLocationDetectionDurationInMillis(long j) {
        this.b = j;
    }

    public void setRequestSecureCreative(boolean z) {
        this.f = z;
    }

    public void setUseInternalBrowser(boolean z) {
        this.c = z;
    }

    public void setUserInfo(com.pubmatic.sdk.common.models.k kVar) {
        this.h = kVar;
    }
}
