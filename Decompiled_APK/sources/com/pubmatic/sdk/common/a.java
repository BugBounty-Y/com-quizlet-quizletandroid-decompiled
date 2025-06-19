package com.pubmatic.sdk.common;

import android.content.Context;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public class a {
    public static final String KEY_SELECTED_REWARD = "selected_reward";

    /* renamed from: com.pubmatic.sdk.common.a$a, reason: collision with other inner class name */
    public enum EnumC0007a {
        All(0),
        Verbose(1),
        Debug(2),
        Info(3),
        Warn(4),
        Error(5),
        Off(6);

        final int b;

        EnumC0007a(int i) {
            this.b = i;
        }

        public int getLevel() {
            return this.b;
        }
    }

    public static void addExternalUserId(@NonNull com.pubmatic.sdk.common.models.g gVar) {
        i.getSdkConfig().addExternalUserId(gVar);
    }

    public static void allowAdvertisingId(boolean z) {
        i.getSdkConfig().allowAdvertisingId(z);
    }

    public static void allowLocationAccess(boolean z) {
        i.getSdkConfig().allowLocationAccess(z);
    }

    public static com.pubmatic.sdk.common.models.d getApplicationInfo() {
        return i.getSdkConfig().getApplicationInfo();
    }

    @NonNull
    public static List<com.pubmatic.sdk.common.models.g> getExternalUserIds() {
        Map<String, List<com.pubmatic.sdk.common.models.g>> externalUserIds = i.getSdkConfig().getExternalUserIds();
        ArrayList arrayList = new ArrayList();
        Iterator<Map.Entry<String, List<com.pubmatic.sdk.common.models.g>>> it2 = externalUserIds.entrySet().iterator();
        while (it2.hasNext()) {
            arrayList.addAll(it2.next().getValue());
        }
        return arrayList;
    }

    public static com.pubmatic.sdk.common.models.k getUserInfo() {
        return i.getSdkConfig().getUserInfo();
    }

    public static String getVersion() {
        return "3.7.0";
    }

    public static void initialize(@NonNull Context context, @NonNull b bVar, @NonNull c cVar) {
        e.INSTANCE.initialize(context, bVar, cVar);
    }

    public static void removeAllExternalUserIds() {
        i.getSdkConfig().removeAllExternalUserIds();
    }

    public static void removeExternalUserIds(@NonNull String str) {
        i.getSdkConfig().removeExternalUserIds(str);
    }

    public static void setApplicationInfo(com.pubmatic.sdk.common.models.d dVar) {
        i.getSdkConfig().setApplicationInfo(dVar);
    }

    public static void setCoppa(boolean z) {
        i.getSdkConfig().setCoppa(z);
    }

    public static void setLocation(com.pubmatic.sdk.common.models.h hVar) {
        i.getSdkConfig().setLocation(hVar);
    }

    public static void setLogLevel(EnumC0007a enumC0007a) {
        POBLog.setLogLevel(enumC0007a);
    }

    public static void setSSLEnabled(boolean z) {
        i.getSdkConfig().setRequestSecureCreative(z);
    }

    public static void setUseInternalBrowser(boolean z) {
        i.getSdkConfig().setUseInternalBrowser(z);
    }

    public static void setUserInfo(com.pubmatic.sdk.common.models.k kVar) {
        i.getSdkConfig().setUserInfo(kVar);
    }
}
