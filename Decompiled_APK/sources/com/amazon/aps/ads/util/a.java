package com.amazon.aps.ads.util;

import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public static final a b = new a();
    public final HashMap a = new HashMap();

    public final synchronized Object a(Class type, String key) {
        Object obj;
        try {
            Intrinsics.checkNotNullParameter(key, "key");
            Intrinsics.checkNotNullParameter(type, "type");
            if (this.a.containsKey(key) && (obj = this.a.get(key)) != null) {
                if (!(obj instanceof Long) || !Intrinsics.b(Long.TYPE, type)) {
                    if ((!(obj instanceof Float) || !Intrinsics.b(Float.TYPE, type)) && ((!(obj instanceof Boolean) || !Intrinsics.b(Boolean.TYPE, type)) && ((!(obj instanceof Integer) || !Intrinsics.b(Integer.TYPE, type)) && ((!(obj instanceof String) || !String.class.equals(type)) && !obj.getClass().equals(type))))) {
                        throw new IllegalArgumentException("Default and storage type are not same");
                    }
                }
                return obj;
            }
            return null;
        } finally {
        }
    }
}
