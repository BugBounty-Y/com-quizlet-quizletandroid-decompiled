package com.google.gson;

import java.io.Serializable;
import java.math.BigInteger;

/* loaded from: classes2.dex */
public final class p extends m {
    public final Serializable a;

    public p(Boolean bool) {
        bool.getClass();
        this.a = bool;
    }

    public static boolean e(p pVar) {
        Serializable serializable = pVar.a;
        if (!(serializable instanceof Number)) {
            return false;
        }
        Number number = (Number) serializable;
        return (number instanceof BigInteger) || (number instanceof Long) || (number instanceof Integer) || (number instanceof Short) || (number instanceof Byte);
    }

    @Override // com.google.gson.m
    public final long a() {
        return this.a instanceof Number ? c().longValue() : Long.parseLong(b());
    }

    @Override // com.google.gson.m
    public final String b() {
        Serializable serializable = this.a;
        return serializable instanceof Number ? c().toString() : serializable instanceof Boolean ? ((Boolean) serializable).toString() : (String) serializable;
    }

    public final Number c() {
        Serializable serializable = this.a;
        return serializable instanceof String ? new com.google.gson.internal.h((String) serializable) : (Number) serializable;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || p.class != obj.getClass()) {
            return false;
        }
        p pVar = (p) obj;
        Serializable serializable = this.a;
        Serializable serializable2 = pVar.a;
        if (serializable == null) {
            return serializable2 == null;
        }
        if (e(this) && e(pVar)) {
            return c().longValue() == pVar.c().longValue();
        }
        if (!(serializable instanceof Number) || !(serializable2 instanceof Number)) {
            return serializable.equals(serializable2);
        }
        double dDoubleValue = c().doubleValue();
        double dDoubleValue2 = pVar.c().doubleValue();
        if (dDoubleValue != dDoubleValue2) {
            return Double.isNaN(dDoubleValue) && Double.isNaN(dDoubleValue2);
        }
        return true;
    }

    public final int hashCode() {
        long jDoubleToLongBits;
        Serializable serializable = this.a;
        if (serializable == null) {
            return 31;
        }
        if (e(this)) {
            jDoubleToLongBits = c().longValue();
        } else {
            if (!(serializable instanceof Number)) {
                return serializable.hashCode();
            }
            jDoubleToLongBits = Double.doubleToLongBits(c().doubleValue());
        }
        return (int) (jDoubleToLongBits ^ (jDoubleToLongBits >>> 32));
    }

    public p(Number number) {
        number.getClass();
        this.a = number;
    }

    public p(String str) {
        str.getClass();
        this.a = str;
    }
}
