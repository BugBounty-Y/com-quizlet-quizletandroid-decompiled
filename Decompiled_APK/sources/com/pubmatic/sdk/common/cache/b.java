package com.pubmatic.sdk.common.cache;

import android.content.Context;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.h;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.models.i;
import com.pubmatic.sdk.common.network.d;
import com.pubmatic.sdk.common.network.g;
import com.pubmatic.sdk.common.utility.o;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class b {

    @NonNull
    private final Context b;

    @NonNull
    private final g c;
    private String f;
    private final String a = "POBCacheManager";

    @NonNull
    private final Map<String, i> d = Collections.synchronizedMap(new HashMap());

    @NonNull
    private final Set<String> e = Collections.synchronizedSet(new HashSet());

    @NonNull
    private final Object g = new Object();

    public class a implements Runnable {
        final /* synthetic */ com.pubmatic.sdk.common.viewability.c a;

        public a(com.pubmatic.sdk.common.viewability.c cVar) {
            this.a = cVar;
        }

        @Override // java.lang.Runnable
        public void run() {
            o.runOnMainThread(new c(this, o.readFromAssets(b.this.b, "omsdk-v1.js")));
        }
    }

    /* renamed from: com.pubmatic.sdk.common.cache.b$b, reason: collision with other inner class name */
    public class C0009b implements d {
        final /* synthetic */ String a;

        public C0009b(String str) {
            this.a = str;
        }

        @Override // com.pubmatic.sdk.common.network.d
        /* renamed from: a, reason: merged with bridge method [inline-methods] */
        public void onSuccess(String str) {
            POBLog.debug("POBCacheManager", "Received profile config response - %s", str);
            if (o.isNullOrEmpty(str)) {
                b.this.a(new h(1007, "Failed to fetch the config."), this.a);
                return;
            }
            try {
                b.this.d.put(this.a, i.build(new JSONObject(str)));
                b.this.e.remove(this.a);
            } catch (JSONException e) {
                b.this.a(new h(1007, e.getMessage() != null ? e.getMessage() : "Error while parsing profile info."), this.a);
            }
        }

        @Override // com.pubmatic.sdk.common.network.d
        public void onFailure(@NonNull h hVar) {
            b.this.a(hVar, this.a);
        }
    }

    public b(@NonNull Context context, @NonNull g gVar) {
        this.b = context.getApplicationContext();
        this.c = gVar;
    }

    public i getProfileInfo(@NonNull String str) {
        return this.d.get(str);
    }

    public void loadInternalServiceJS(@NonNull com.pubmatic.sdk.common.viewability.c cVar) {
        synchronized (this.g) {
            try {
                String str = this.f;
                if (str != null) {
                    cVar.onMeasurementScriptReceived(str);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (this.f == null) {
            loadLocalOmidScript(cVar);
        }
    }

    public void loadLocalOmidScript(com.pubmatic.sdk.common.viewability.c cVar) {
        o.runOnBackgroundThread(new a(cVar));
    }

    public void requestProfileConfiguration(@NonNull String str, int i, Integer num) {
        String mappingKey = o.getMappingKey(i, num);
        if (this.e.contains(mappingKey)) {
            return;
        }
        i iVar = this.d.get(mappingKey);
        if (iVar == null || iVar.isProfileInfoExpired()) {
            if (!com.pubmatic.sdk.common.network.i.isNetworkAvailable(this.b)) {
                a(new h(1003, "No network available"), mappingKey);
                return;
            }
            String strA = a(str, i, num);
            com.pubmatic.sdk.common.network.a aVar = new com.pubmatic.sdk.common.network.a();
            aVar.setUrl(strA);
            POBLog.debug("POBCacheManager", "Requesting profile config with url - : %s", strA);
            aVar.setTimeout(1000);
            this.e.add(mappingKey);
            this.c.sendRequest(aVar, new C0009b(mappingKey));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(@NonNull h hVar, @NonNull String str) {
        POBLog.error("POBCacheManager", "Failed to fetch config with error: %s", hVar.getErrorMessage());
        if (hVar.getErrorCode() != 1003) {
            this.d.put(str, new i());
        }
        this.e.remove(str);
    }

    private String a(String str, int i, Integer num) {
        if (num != null) {
            Locale locale = Locale.ENGLISH;
            StringBuilder sb = new StringBuilder("https://ads.pubmatic.com/AdServer/js/pwt/");
            sb.append(str);
            sb.append("/");
            sb.append(i);
            sb.append("/");
            return assistantMode.refactored.a.l(sb, num, "/config.json");
        }
        Locale locale2 = Locale.ENGLISH;
        return "https://ads.pubmatic.com/AdServer/js/pwt/" + str + "/" + i + "/config.json";
    }
}
