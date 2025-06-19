package com.pubmatic.sdk.common.network;

import android.annotation.SuppressLint;
import android.net.Uri;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.network.a;
import com.pubmatic.sdk.video.c;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public class n {

    @NonNull
    private final g a;
    private com.pubmatic.sdk.common.models.f b;

    public class a implements d {
        final /* synthetic */ String a;

        public a(String str) {
            this.a = str;
        }

        @Override // com.pubmatic.sdk.common.network.d
        /* renamed from: a, reason: merged with bridge method [inline-methods] */
        public void onSuccess(String str) {
            POBLog.debug("PMTrackerHandler", "Successfully executed tracker url : " + this.a, new Object[0]);
        }

        @Override // com.pubmatic.sdk.common.network.d
        public void onFailure(@NonNull com.pubmatic.sdk.common.h hVar) {
            POBLog.error("PMTrackerHandler", "Failed to execute tracker url : " + this.a, "\n Error : " + hVar.getErrorMessage());
        }
    }

    public n(@NonNull g gVar) {
        this.a = gVar;
    }

    @NonNull
    public static List<String> sanitizeURLScheme(List<String> list, boolean z) {
        ArrayList arrayList = new ArrayList();
        if (list == null) {
            POBLog.debug("PMTrackerHandler", "Unable to sanitize urls as list is null", new Object[0]);
            return arrayList;
        }
        Iterator<String> it2 = list.iterator();
        while (it2.hasNext()) {
            String strSanitizeURLScheme = sanitizeURLScheme(it2.next(), z);
            if (strSanitizeURLScheme != null) {
                arrayList.add(strSanitizeURLScheme);
            }
        }
        return arrayList;
    }

    @SuppressLint({"SetJavaScriptEnabled"})
    public void executeJsScripts(@NonNull com.pubmatic.sdk.common.view.c cVar, @NonNull String str) {
        POBLog.debug("PMTrackerHandler", AbstractC0147y.d("Executing js tracker script: ", str), new Object[0]);
        cVar.getSettings().setJavaScriptEnabled(true);
        cVar.loadDataWithBaseURL(null, str, "text/html", StandardCharsets.UTF_8.name(), null);
    }

    public void handleTrackersForError(List<String> list, Map<Object, Object> map, Map<String, String> map2) {
        if (list == null || list.size() <= 0) {
            return;
        }
        for (String strBuildUriWithQueryParams : list) {
            Uri uri = Uri.parse(strBuildUriWithQueryParams);
            String host = uri.getHost();
            if (map2 != null && !map2.isEmpty() && host != null && host.contains("pubmatic.com")) {
                strBuildUriWithQueryParams = com.pubmatic.sdk.common.utility.o.buildUriWithQueryParams(uri, map2);
            }
            sendTracker(strBuildUriWithQueryParams, map);
        }
    }

    public void sendTracker(String str) {
        if (com.pubmatic.sdk.common.utility.o.isNullOrEmpty(str)) {
            POBLog.error("PMTrackerHandler", AbstractC0147y.d("Failed to execute tracker url: ", str), new Object[0]);
            return;
        }
        POBLog.debug("PMTrackerHandler", "Executing tracker for url: %s", str);
        com.pubmatic.sdk.common.network.a aVar = new com.pubmatic.sdk.common.network.a();
        aVar.setUrl(str);
        aVar.setRetryCount(3);
        aVar.setRequestMethod(a.EnumC0011a.GET);
        aVar.setTimeout(c.a.DEFAULT_MEDIA_URI_TIMEOUT);
        if (this.b != null) {
            HashMap map = new HashMap();
            map.put("User-Agent", this.b.getUserAgent());
            aVar.setHeaders(map);
        }
        this.a.sendRequest(aVar, new a(str));
    }

    public void sendTrackers(List<String> list) {
        if (list == null || list.isEmpty()) {
            POBLog.error("PMTrackerHandler", "Failed to execute tracker url: " + list, new Object[0]);
        } else {
            Iterator<String> it2 = list.iterator();
            while (it2.hasNext()) {
                sendTracker(it2.next());
            }
        }
    }

    public void setDeviceInfo(com.pubmatic.sdk.common.models.f fVar) {
        this.b = fVar;
    }

    public void sendTrackers(List<String> list, Map<Object, Object> map) {
        if (list == null || list.size() <= 0) {
            return;
        }
        Iterator<String> it2 = list.iterator();
        while (it2.hasNext()) {
            sendTracker(it2.next(), map);
        }
    }

    public static String sanitizeURLScheme(String str, boolean z) {
        try {
            if (!com.pubmatic.sdk.common.utility.o.isNullOrEmpty(str)) {
                Uri uri = Uri.parse(str);
                if (uri == null || uri.getScheme() != null) {
                    return str;
                }
                return uri.buildUpon().scheme(z ? "https" : "http").build().toString();
            }
            POBLog.debug("PMTrackerHandler", "Unable to sanitize url - %s", str);
            return null;
        } catch (Exception e) {
            POBLog.debug("PMTrackerHandler", "Error occurred while sanitizing url %s. Reason - %s", str, e.getMessage());
            return null;
        }
    }

    public void sendTracker(String str, Map<Object, Object> map) {
        if (!com.pubmatic.sdk.common.utility.o.isNullOrEmpty(str)) {
            if (map != null && map.size() > 0) {
                for (Map.Entry<Object, Object> entry : map.entrySet()) {
                    str = str.replace(String.valueOf(entry.getKey()), String.valueOf(entry.getValue()));
                }
            }
            sendTracker(str);
            return;
        }
        POBLog.error("PMTrackerHandler", "Empty tracker url.", new Object[0]);
    }

    public void sendTracker(String str, String str2, String str3) {
        if (!com.pubmatic.sdk.common.utility.o.isNullOrEmpty(str)) {
            if (str2 != null && str3 != null) {
                str = str.replace(str2, str3);
            }
            sendTracker(str);
            return;
        }
        POBLog.error("PMTrackerHandler", "Unable to send tracker for url - %s.", str);
    }
}
