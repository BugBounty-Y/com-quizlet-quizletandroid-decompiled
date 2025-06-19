package com.appsflyer.internal;

import java.util.HashMap;

/* loaded from: classes.dex */
public class AFa1nSDK extends HashMap<Integer, String> {
    private static AFa1nSDK getMonetizationNetwork;
    private final Object getRevenue = new Object();

    private AFa1nSDK() {
    }

    public static synchronized AFa1nSDK afErrorLog() {
        try {
            if (getMonetizationNetwork == null) {
                getMonetizationNetwork = new AFa1nSDK();
            }
        } catch (Throwable th) {
            throw th;
        }
        return getMonetizationNetwork;
    }

    @Override // java.util.HashMap, java.util.AbstractMap, java.util.Map
    public String put(Integer num, String str) {
        String str2;
        synchronized (this.getRevenue) {
            str2 = (String) super.put((AFa1nSDK) num, (Integer) str);
        }
        return str2;
    }

    @Override // java.util.HashMap, java.util.Map
    public boolean remove(Object obj, Object obj2) {
        boolean zRemove;
        synchronized (this.getRevenue) {
            zRemove = super.remove(obj, obj2);
        }
        return zRemove;
    }

    @Override // java.util.HashMap, java.util.AbstractMap, java.util.Map
    public String remove(Object obj) {
        String str;
        synchronized (this.getRevenue) {
            str = (String) super.remove(obj);
        }
        return str;
    }
}
