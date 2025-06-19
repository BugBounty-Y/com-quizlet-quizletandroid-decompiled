package com.pubmatic.sdk.common.models;

import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.utility.o;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class e {
    private final String a;

    @NonNull
    private final String b;
    private int c;

    @NonNull
    private final Map<String, j> d;
    private JSONObject e;

    public e(@NonNull String str) {
        this(str, null);
    }

    public void addSegment(@NonNull j jVar) {
        if (jVar == null || o.isNullOrEmpty(jVar.getSegId())) {
            POBLog.warn("POBDataProvider", "%s is null or required fields are not available", "segments");
            return;
        }
        String segId = jVar.getSegId();
        if (this.d.containsKey(segId)) {
            POBLog.warn("POBDataProvider", "%s with duplicate %s not allowed", "segments", "id");
        } else {
            this.d.put(segId, jVar);
        }
    }

    public JSONObject getExt() {
        return this.e;
    }

    public String getId() {
        return this.a;
    }

    @NonNull
    public String getName() {
        return this.b;
    }

    public int getSegTax() {
        return this.c;
    }

    public j getSegment(@NonNull String str) {
        return this.d.get(str);
    }

    @NonNull
    public Map<String, j> getSegments() {
        return this.d;
    }

    public void removeAllSegments() {
        this.d.clear();
    }

    public j removeSegment(@NonNull String str) {
        return this.d.remove(str);
    }

    public void setExt(@NonNull JSONObject jSONObject) {
        this.e = jSONObject;
    }

    public void setSegTax(int i) {
        this.c = i;
    }

    public e(@NonNull String str, String str2) {
        this.a = str2;
        this.b = str;
        this.c = 0;
        this.d = Collections.synchronizedMap(new HashMap());
    }
}
