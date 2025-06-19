package com.pubmatic.sdk.common.models;

import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.utility.o;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public class k {
    private int a;
    private a b;
    private String c;
    private String d;
    private String e;
    private String f;
    private String g;

    @NonNull
    private final Map<String, e> h = Collections.synchronizedMap(new HashMap());

    public enum a {
        MALE("M"),
        FEMALE("F"),
        OTHER("O");

        private final String b;

        a(String str) {
            this.b = str;
        }

        public String getValue() {
            return this.b;
        }
    }

    public void addDataProvider(@NonNull e eVar) {
        if (eVar == null || o.isNullOrEmpty(eVar.getName()) || eVar.getSegments().isEmpty()) {
            POBLog.warn("POBUserInfo", "%s is null or required fields are not available", "Data Provider");
            return;
        }
        String name = eVar.getName();
        if (this.h.containsKey(name)) {
            POBLog.warn("POBUserInfo", "%s with duplicate %s not allowed", "Data Provider", "provider name");
        } else {
            this.h.put(name, eVar);
        }
    }

    public int getBirthYear() {
        return this.a;
    }

    public String getCity() {
        return this.c;
    }

    public e getDataProvider(@NonNull String str) {
        return this.h.get(str);
    }

    @NonNull
    public List<e> getDataProviders() {
        ArrayList arrayList = new ArrayList();
        for (Map.Entry<String, e> entry : this.h.entrySet()) {
            if (entry != null) {
                arrayList.add(entry.getValue());
            }
        }
        return arrayList;
    }

    public a getGender() {
        return this.b;
    }

    public String getKeywords() {
        return this.g;
    }

    public String getMetro() {
        return this.d;
    }

    public String getRegion() {
        return this.f;
    }

    public String getZip() {
        return this.e;
    }

    public void removeAllDataProviders() {
        this.h.clear();
    }

    public e removeDataProvider(@NonNull String str) {
        return this.h.remove(str);
    }

    public void setBirthYear(int i) {
        if (i > 0) {
            this.a = i;
        }
    }

    public void setCity(@NonNull String str) {
        this.c = str;
    }

    public void setGender(@NonNull a aVar) {
        this.b = aVar;
    }

    public void setKeywords(String str) {
        this.g = str;
    }

    public void setMetro(@NonNull String str) {
        this.d = str;
    }

    public void setRegion(@NonNull String str) {
        this.f = str;
    }

    public void setZip(@NonNull String str) {
        this.e = str;
    }
}
