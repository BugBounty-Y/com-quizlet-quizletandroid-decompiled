package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class Vx {
    public static final Vx b = new Vx();
    public final HashMap a = new HashMap();

    public final synchronized void a(String str, AbstractC2547qw abstractC2547qw) {
        try {
            HashMap map = this.a;
            if (!map.containsKey(str)) {
                map.put(str, abstractC2547qw);
                return;
            }
            if (((AbstractC2547qw) map.get(str)).equals(abstractC2547qw)) {
                return;
            }
            throw new GeneralSecurityException("Parameters object with name " + str + " already exists (" + String.valueOf(map.get(str)) + "), cannot insert " + String.valueOf(abstractC2547qw));
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized void b(Map map) {
        for (Map.Entry entry : map.entrySet()) {
            a((String) entry.getKey(), (AbstractC2547qw) entry.getValue());
        }
    }
}
