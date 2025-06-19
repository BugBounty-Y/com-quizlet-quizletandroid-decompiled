package com.comscore.util.unittest;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.os.Build;
import com.comscore.util.cpp.CppJavaBinder;
import com.google.firebase.perf.network.FirebasePerfUrlConnection;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;

/* loaded from: classes.dex */
public class TestUtils {
    public static int getExceptionCounter(CppJavaBinder cppJavaBinder) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Method declaredMethod = CppJavaBinder.class.getDeclaredMethod("getExceptionCounter", null);
        declaredMethod.setAccessible(true);
        return ((Integer) declaredMethod.invoke(cppJavaBinder, null)).intValue();
    }

    public static int getExceptionCounterStatic(Class<?> cls) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Method declaredMethod = cls.getDeclaredMethod("getExceptionCounter", null);
        declaredMethod.setAccessible(true);
        return ((Integer) declaredMethod.invoke(null, null)).intValue();
    }

    public static native boolean isAnalyticsInitialized();

    public static boolean isServerReachable(Context context, String str) throws IOException {
        NetworkCapabilities networkCapabilities;
        ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService("connectivity");
        if (Build.VERSION.SDK_INT >= 29 && (networkCapabilities = connectivityManager.getNetworkCapabilities(connectivityManager.getActiveNetwork())) != null && (networkCapabilities.hasTransport(0) || networkCapabilities.hasTransport(1) || networkCapabilities.hasTransport(3))) {
            try {
                HttpURLConnection httpURLConnection = (HttpURLConnection) ((URLConnection) FirebasePerfUrlConnection.instrument(new URL(str).openConnection()));
                httpURLConnection.setConnectTimeout(3000);
                httpURLConnection.connect();
                if (httpURLConnection.getResponseCode() != -1) {
                    return true;
                }
            } catch (IOException unused) {
            }
        }
        return false;
    }
}
