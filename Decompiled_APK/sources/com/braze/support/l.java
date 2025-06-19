package com.braze.support;

import androidx.compose.ui.node.B;
import com.braze.AbstractC1484j;
import com.braze.support.BrazeLogger;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import kotlin.collections.CollectionsKt;
import kotlin.collections.U;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.C;

/* loaded from: classes.dex */
public abstract class l {
    public static final String a = BrazeLogger.INSTANCE.getBrazeLogTag("HttpUtils");
    public static final SimpleDateFormat b = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US);

    public static final Long a(String str) throws ParseException {
        try {
            Double dE = C.e(str);
            if (dE != null) {
                return Long.valueOf((long) (dE.doubleValue() * 1000));
            }
            Date date = b.parse(str);
            if (date != null) {
                return Long.valueOf(date.getTime() - DateTimeUtils.nowInMilliseconds());
            }
            return null;
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, a, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new w(str, 10), 8, (Object) null);
            return null;
        }
    }

    public static final String b(String str) {
        return AbstractC1484j.a("Could not parse http-date value: ", str);
    }

    public static final LinkedHashMap a(Map map) {
        Intrinsics.checkNotNullParameter(map, "<this>");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (Map.Entry entry : map.entrySet()) {
            if (((String) entry.getKey()) != null) {
                linkedHashMap.put(entry.getKey(), entry.getValue());
            }
        }
        LinkedHashMap linkedHashMap2 = new LinkedHashMap(U.a(linkedHashMap.size()));
        for (Map.Entry entry2 : linkedHashMap.entrySet()) {
            Object key = entry2.getKey();
            Intrinsics.d(key);
            Locale locale = Locale.US;
            linkedHashMap2.put(B.k(locale, "US", (String) key, locale, "toLowerCase(...)"), entry2.getValue());
        }
        LinkedHashMap linkedHashMap3 = new LinkedHashMap(U.a(linkedHashMap2.size()));
        for (Map.Entry entry3 : linkedHashMap2.entrySet()) {
            linkedHashMap3.put(entry3.getKey(), CollectionsKt.S((Iterable) entry3.getValue(), null, null, null, null, 63));
        }
        return linkedHashMap3;
    }
}
