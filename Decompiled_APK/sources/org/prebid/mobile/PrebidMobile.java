package org.prebid.mobile;

import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.LinkedHashMap;

/* loaded from: classes3.dex */
public abstract class PrebidMobile {
    public static int a = 2000;
    public static String b = "";
    public static Host c = Host.b;
    public static final LinkedHashMap d = new LinkedHashMap();
    public static final HashMap e = new HashMap();
    public static final WeakReference f = new WeakReference(null);

    public enum LogLevel {
        NONE(-1),
        /* JADX INFO: Fake field, exist only in values array */
        DEBUG(3),
        /* JADX INFO: Fake field, exist only in values array */
        WARN(5),
        /* JADX INFO: Fake field, exist only in values array */
        ERROR(6);

        LogLevel(int i) {
        }
    }
}
