package com.appsflyer.internal;

import android.graphics.Color;
import android.media.AudioTrack;
import android.os.Process;
import android.os.SystemClock;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewConfiguration;
import com.appsflyer.internal.AFg1eSDK;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class AFg1dSDK {
    private final LinkedHashMap<String, Object> getRevenue;
    public static final Object getMonetizationNetwork = new Object() { // from class: com.appsflyer.internal.AFg1dSDK.1
        public final boolean equals(Object obj) {
            return obj == this || obj == null;
        }

        public final int hashCode() {
            return 0;
        }

        public final String toString() {
            return "null";
        }
    };
    private static final Double getMediationNetwork = Double.valueOf(-0.0d);

    public AFg1dSDK() {
        this.getRevenue = new LinkedHashMap<>();
    }

    public static Object getCurrencyIso4217Code(Object obj) throws Throwable {
        if (obj == null) {
            return getMonetizationNetwork;
        }
        if (((Class) AFa1kSDK.getCurrencyIso4217Code(Color.red(0) + 321, (char) (2133 - View.MeasureSpec.getMode(0)), 36 - TextUtils.indexOf("", "", 0))).isInstance(obj) || (obj instanceof AFg1dSDK)) {
            return obj;
        }
        if (obj instanceof JSONArray) {
            try {
                Object[] objArr = {obj.toString()};
                Map map = AFa1kSDK.i;
                Object declaredConstructor = map.get(-22273894);
                if (declaredConstructor == null) {
                    declaredConstructor = ((Class) AFa1kSDK.getCurrencyIso4217Code(TextUtils.indexOf((CharSequence) "", '0', 0, 0) + 322, (char) (2133 - View.MeasureSpec.makeMeasureSpec(0, 0)), (ViewConfiguration.getTapTimeout() >> 16) + 36)).getDeclaredConstructor(String.class);
                    map.put(-22273894, declaredConstructor);
                }
                obj = ((Constructor) declaredConstructor).newInstance(objArr);
                return obj;
            } catch (Throwable th) {
                Throwable cause = th.getCause();
                if (cause != null) {
                    throw cause;
                }
                throw th;
            }
        }
        if (obj instanceof JSONObject) {
            return new AFg1dSDK(obj.toString());
        }
        if (obj.equals(getMonetizationNetwork)) {
            return obj;
        }
        if (obj instanceof Collection) {
            try {
                Object[] objArr2 = {(Collection) obj};
                Map map2 = AFa1kSDK.i;
                Object declaredConstructor2 = map2.get(1460610771);
                if (declaredConstructor2 == null) {
                    declaredConstructor2 = ((Class) AFa1kSDK.getCurrencyIso4217Code(321 - View.MeasureSpec.getSize(0), (char) (2133 - (ViewConfiguration.getMinimumFlingVelocity() >> 16)), (ViewConfiguration.getFadingEdgeLength() >> 16) + 36)).getDeclaredConstructor(Collection.class);
                    map2.put(1460610771, declaredConstructor2);
                }
                return ((Constructor) declaredConstructor2).newInstance(objArr2);
            } catch (Throwable th2) {
                Throwable cause2 = th2.getCause();
                if (cause2 != null) {
                    throw cause2;
                }
                throw th2;
            }
        }
        if (obj.getClass().isArray()) {
            try {
                Object[] objArr3 = {obj};
                Map map3 = AFa1kSDK.i;
                Object declaredConstructor3 = map3.get(-1726787512);
                if (declaredConstructor3 == null) {
                    declaredConstructor3 = ((Class) AFa1kSDK.getCurrencyIso4217Code(320 - TextUtils.indexOf((CharSequence) "", '0', 0, 0), (char) (2133 - Color.alpha(0)), Color.green(0) + 36)).getDeclaredConstructor(Object.class);
                    map3.put(-1726787512, declaredConstructor3);
                }
                return ((Constructor) declaredConstructor3).newInstance(objArr3);
            } catch (Throwable th3) {
                Throwable cause3 = th3.getCause();
                if (cause3 != null) {
                    throw cause3;
                }
                throw th3;
            }
        }
        if (obj instanceof Map) {
            return new AFg1dSDK((Map) obj);
        }
        if ((obj instanceof Boolean) || (obj instanceof Byte) || (obj instanceof Character) || (obj instanceof Double) || (obj instanceof Float) || (obj instanceof Integer) || (obj instanceof Long) || (obj instanceof Short) || (obj instanceof String)) {
            return obj;
        }
        if (obj.getClass().getPackage().getName().startsWith("java.")) {
            return obj.toString();
        }
        return null;
        return null;
    }

    public static String getMediationNetwork(Number number) throws Throwable {
        if (number == null) {
            throw new AFg1mSDK("Number must be non-null");
        }
        double dDoubleValue = number.doubleValue();
        try {
            Object[] objArr = {Double.valueOf(dDoubleValue)};
            Map map = AFa1kSDK.i;
            Object declaredMethod = map.get(1011674371);
            if (declaredMethod == null) {
                declaredMethod = ((Class) AFa1kSDK.getCurrencyIso4217Code(TextUtils.indexOf((CharSequence) "", '0', 0, 0) + 285, (char) View.MeasureSpec.getMode(0), Color.rgb(0, 0, 0) + 16777253)).getDeclaredMethod("getMonetizationNetwork", Double.TYPE);
                map.put(1011674371, declaredMethod);
            }
            ((Double) ((Method) declaredMethod).invoke(null, objArr)).getClass();
            if (number.equals(getMediationNetwork)) {
                return "-0";
            }
            long jLongValue = number.longValue();
            return dDoubleValue == ((double) jLongValue) ? Long.toString(jLongValue) : number.toString();
        } catch (Throwable th) {
            Throwable cause = th.getCause();
            if (cause != null) {
                throw cause;
            }
            throw th;
        }
    }

    public final void AFAdRevenueData(AFg1eSDK aFg1eSDK) throws AFg1mSDK {
        aFg1eSDK.getCurrencyIso4217Code(AFg1eSDK.AFa1uSDK.EMPTY_OBJECT, "{");
        for (Map.Entry<String, Object> entry : this.getRevenue.entrySet()) {
            String key = entry.getKey();
            if (key == null) {
                throw new AFg1mSDK("Names must be non-null");
            }
            aFg1eSDK.getMonetizationNetwork();
            aFg1eSDK.getCurrencyIso4217Code(key);
            aFg1eSDK.getRevenue(entry.getValue());
        }
        aFg1eSDK.AFAdRevenueData(AFg1eSDK.AFa1uSDK.EMPTY_OBJECT, AFg1eSDK.AFa1uSDK.NONEMPTY_OBJECT, "}");
    }

    public final String toString() {
        try {
            AFg1eSDK aFg1eSDK = new AFg1eSDK();
            AFAdRevenueData(aFg1eSDK);
            return aFg1eSDK.toString();
        } catch (AFg1mSDK unused) {
            return null;
        }
    }

    public AFg1dSDK(Map map) {
        this();
        for (Map.Entry entry : map.entrySet()) {
            String str = (String) entry.getKey();
            if (str != null) {
                this.getRevenue.put(str, getCurrencyIso4217Code(entry.getValue()));
            } else {
                throw new NullPointerException("key == null");
            }
        }
    }

    private AFg1dSDK(Object obj) throws Throwable {
        try {
            Map map = AFa1kSDK.i;
            Object declaredMethod = map.get(-865524410);
            if (declaredMethod == null) {
                declaredMethod = ((Class) AFa1kSDK.getCurrencyIso4217Code(357 - View.MeasureSpec.getSize(0), (char) (View.MeasureSpec.getMode(0) + 6866), 38 - (SystemClock.uptimeMillis() > 0L ? 1 : (SystemClock.uptimeMillis() == 0L ? 0 : -1)))).getDeclaredMethod("getRevenue", null);
                map.put(-865524410, declaredMethod);
            }
            Object objInvoke = ((Method) declaredMethod).invoke(obj, null);
            if (objInvoke instanceof AFg1dSDK) {
                this.getRevenue = ((AFg1dSDK) objInvoke).getRevenue;
                return;
            }
            Object[] objArr = {objInvoke, "AFJsonObject"};
            Object declaredMethod2 = map.get(464586448);
            if (declaredMethod2 == null) {
                declaredMethod2 = ((Class) AFa1kSDK.getCurrencyIso4217Code((ViewConfiguration.getFadingEdgeLength() >> 16) + 284, (char) View.resolveSize(0, 0), 37 - (ViewConfiguration.getJumpTapTimeout() >> 16))).getDeclaredMethod("getRevenue", Object.class, String.class);
                map.put(464586448, declaredMethod2);
            }
            throw ((Throwable) ((Method) declaredMethod2).invoke(null, objArr));
        } catch (Throwable th) {
            Throwable cause = th.getCause();
            if (cause == null) {
                throw th;
            }
            throw cause;
        }
    }

    /* JADX WARN: Illegal instructions before constructor call */
    private AFg1dSDK(String str) throws Throwable {
        try {
            Object[] objArr = {str};
            Map map = AFa1kSDK.i;
            Object declaredConstructor = map.get(1502086856);
            if (declaredConstructor == null) {
                declaredConstructor = ((Class) AFa1kSDK.getCurrencyIso4217Code(357 - (ViewConfiguration.getTapTimeout() >> 16), (char) (6865 - Process.getGidForName("")), Color.red(0) + 37)).getDeclaredConstructor(String.class);
                map.put(1502086856, declaredConstructor);
            }
            this(((Constructor) declaredConstructor).newInstance(objArr));
        } catch (Throwable th) {
            Throwable cause = th.getCause();
            if (cause == null) {
                throw th;
            }
            throw cause;
        }
    }

    public final AFg1dSDK getCurrencyIso4217Code(String str, Object obj) throws Throwable {
        if (obj == null) {
            this.getRevenue.remove(str);
            return this;
        }
        if (obj instanceof Number) {
            try {
                Object[] objArr = {Double.valueOf(((Number) obj).doubleValue())};
                Map map = AFa1kSDK.i;
                Object method = map.get(1011674371);
                if (method == null) {
                    method = ((Class) AFa1kSDK.getCurrencyIso4217Code(284 - (AudioTrack.getMinVolume() > DefinitionKt.NO_Float_VALUE ? 1 : (AudioTrack.getMinVolume() == DefinitionKt.NO_Float_VALUE ? 0 : -1)), (char) (ViewConfiguration.getLongPressTimeout() >> 16), 37 - TextUtils.getTrimmedLength(""))).getMethod("getMonetizationNetwork", Double.TYPE);
                    map.put(1011674371, method);
                }
                ((Double) ((Method) method).invoke(null, objArr)).getClass();
            } catch (Throwable th) {
                Throwable cause = th.getCause();
                if (cause != null) {
                    throw cause;
                }
                throw th;
            }
        }
        LinkedHashMap<String, Object> linkedHashMap = this.getRevenue;
        if (str == null) {
            throw new AFg1mSDK("Names must be non-null");
        }
        linkedHashMap.put(str, obj);
        return this;
    }
}
