package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.security.GeneralSecurityException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/* loaded from: classes2.dex */
public final class Fx {
    public static final Logger c = Logger.getLogger(Fx.class.getName());
    public static final Fx d = new Fx();
    public final ConcurrentHashMap a = new ConcurrentHashMap();
    public final ConcurrentHashMap b = new ConcurrentHashMap();

    public final Kx a(Class cls, String str) {
        Kx kxD = d(str);
        if (kxD.b.equals(cls)) {
            return kxD;
        }
        String name = cls.getName();
        String strValueOf = String.valueOf(Kx.class);
        String string = kxD.b.toString();
        StringBuilder sbH = AbstractC0147y.h("Primitive type ", name, " not supported by key manager of type ", strValueOf, ", which only supports: ");
        sbH.append(string);
        throw new GeneralSecurityException(sbH.toString());
    }

    public final synchronized void b(Kx kx) {
        c(kx, 1);
    }

    public final synchronized void c(Kx kx, int i) {
        if (!AbstractC1981ds.j(i)) {
            throw new GeneralSecurityException("Cannot register key manager: FIPS compatibility insufficient");
        }
        e(kx);
    }

    public final synchronized Kx d(String str) {
        ConcurrentHashMap concurrentHashMap;
        concurrentHashMap = this.a;
        if (!concurrentHashMap.containsKey(str)) {
            throw new GeneralSecurityException("No key manager found for key type " + str + ", see https://developers.google.com/tink/faq/registration_errors");
        }
        return (Kx) concurrentHashMap.get(str);
    }

    public final synchronized void e(Kx kx) {
        try {
            String str = kx.a;
            ConcurrentHashMap concurrentHashMap = this.b;
            if (concurrentHashMap.containsKey(str) && !((Boolean) concurrentHashMap.get(str)).booleanValue()) {
                throw new GeneralSecurityException("New keys are already disallowed for key type ".concat(str));
            }
            ConcurrentHashMap concurrentHashMap2 = this.a;
            if (((Kx) concurrentHashMap2.get(str)) != null && !Kx.class.equals(Kx.class)) {
                c.logp(Level.WARNING, "com.google.crypto.tink.internal.KeyManagerRegistry", "insertKeyManager", "Attempted overwrite of a registered key manager for key type ".concat(str));
                throw new GeneralSecurityException("typeUrl (" + str + ") is already registered with " + Kx.class.getName() + ", cannot be re-registered with " + Kx.class.getName());
            }
            concurrentHashMap2.putIfAbsent(str, kx);
            concurrentHashMap.put(str, Boolean.TRUE);
        } catch (Throwable th) {
            throw th;
        }
    }
}
