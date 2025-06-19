package com.google.android.gms.common.util;

import androidx.appcompat.app.K;
import com.google.android.gms.auth.api.signin.internal.h;
import com.google.android.gms.internal.common.j;
import com.google.android.gms.internal.common.k;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public abstract class d {
    static {
        Pattern.compile("^(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}$");
        Pattern.compile("^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$");
        Pattern.compile("^((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)$");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [java.util.Map] */
    /* JADX WARN: Type inference failed for: r1v1, types: [java.util.Map] */
    /* JADX WARN: Type inference failed for: r1v2, types: [java.util.HashMap] */
    public static Map a(URI uri) {
        String strDecode;
        ?? map = Collections.EMPTY_MAP;
        String rawQuery = uri.getRawQuery();
        if (rawQuery != null && rawQuery.length() > 0) {
            map = new HashMap();
            K k = new K((Object) new h(new j('='), 24), false);
            K k2 = new K((Object) new h(new j('&'), 24), true);
            k kVar = new k(k2, rawQuery, (j) ((h) k2.b).b);
            while (kVar.hasNext()) {
                String str = (String) kVar.next();
                str.getClass();
                k kVar2 = new k(k, str, (j) ((h) k.b).b);
                ArrayList arrayList = new ArrayList();
                while (kVar2.hasNext()) {
                    arrayList.add((String) kVar2.next());
                }
                List listUnmodifiableList = Collections.unmodifiableList(arrayList);
                if (listUnmodifiableList.isEmpty() || listUnmodifiableList.size() > 2) {
                    throw new IllegalArgumentException("bad parameter");
                }
                try {
                    String strDecode2 = URLDecoder.decode((String) listUnmodifiableList.get(0), "UTF-8");
                    if (listUnmodifiableList.size() == 2) {
                        try {
                            strDecode = URLDecoder.decode((String) listUnmodifiableList.get(1), "UTF-8");
                        } catch (UnsupportedEncodingException e) {
                            throw new IllegalArgumentException(e);
                        }
                    } else {
                        strDecode = null;
                    }
                    map.put(strDecode2, strDecode);
                } catch (UnsupportedEncodingException e2) {
                    throw new IllegalArgumentException(e2);
                }
            }
        }
        return map;
    }
}
