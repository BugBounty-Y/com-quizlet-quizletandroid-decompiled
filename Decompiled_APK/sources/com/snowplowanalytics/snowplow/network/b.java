package com.snowplowanalytics.snowplow.network;

import android.content.Context;
import android.content.SharedPreferences;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3335e2;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import okhttp3.C5083l;
import okhttp3.n;
import okhttp3.s;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes3.dex */
public final class b implements n {
    public final Set b;
    public final SharedPreferences c;

    public b(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        Set setNewSetFromMap = Collections.newSetFromMap(new ConcurrentHashMap());
        Intrinsics.checkNotNullExpressionValue(setNewSetFromMap, "newSetFromMap(ConcurrentHashMap())");
        this.b = setNewSetFromMap;
        SharedPreferences sharedPreferences = context.getSharedPreferences("cookie_persistance", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "context.getSharedPrefere…CE, Context.MODE_PRIVATE)");
        this.c = sharedPreferences;
        ArrayList arrayList = new ArrayList();
        Map<String, ?> all = sharedPreferences.getAll();
        Intrinsics.checkNotNullExpressionValue(all, "sharedPreferences.all");
        for (Map.Entry<String, ?> entry : all.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            String str = value instanceof String ? (String) value : null;
            if (str != null) {
                try {
                    this.b.add(new a(str));
                } catch (JSONException unused) {
                    Intrinsics.checkNotNullExpressionValue(key, "key");
                    arrayList.add(key);
                }
            }
        }
        if (arrayList.isEmpty()) {
            return;
        }
        SharedPreferences.Editor editorEdit = sharedPreferences.edit();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            editorEdit.remove((String) it2.next());
        }
        editorEdit.apply();
    }

    @Override // okhttp3.n
    public final void a(s url, List cookies) {
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(cookies, "cookies");
        SharedPreferences.Editor editorEdit = this.c.edit();
        Intrinsics.checkNotNullParameter(cookies, "cookies");
        ArrayList arrayList = new ArrayList(cookies.size());
        Iterator it2 = cookies.iterator();
        while (it2.hasNext()) {
            arrayList.add(new a((C5083l) it2.next()));
        }
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            a aVar = (a) it3.next();
            Set set = this.b;
            set.remove(aVar);
            set.add(aVar);
            String strA = aVar.a();
            HashMap map = new HashMap();
            C5083l c5083l = aVar.a;
            map.put("name", c5083l.a);
            map.put("value", c5083l.b);
            map.put("expiresAt", Long.valueOf(c5083l.c));
            map.put("domain", c5083l.d);
            map.put("path", c5083l.e);
            String string = new JSONObject(map).toString();
            Intrinsics.checkNotNullExpressionValue(string, "JSONObject(values).toString()");
            editorEdit.putString(strA, string);
        }
        editorEdit.apply();
    }

    @Override // okhttp3.n
    public final List b(s url) {
        boolean zC;
        Intrinsics.checkNotNullParameter(url, "url");
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        Set<a> set = this.b;
        for (a aVar : set) {
            if (aVar.a.c < System.currentTimeMillis()) {
                arrayList.add(aVar);
            } else {
                C5083l c5083l = aVar.a;
                c5083l.getClass();
                Intrinsics.checkNotNullParameter(url, "url");
                boolean z = c5083l.i;
                String str = c5083l.d;
                if (z) {
                    zC = Intrinsics.b(url.d, str);
                } else {
                    Pattern pattern = C5083l.j;
                    zC = AbstractC3335e2.c(url.d, str);
                }
                if (zC) {
                    String strB = url.b();
                    String str2 = c5083l.e;
                    if (Intrinsics.b(strB, str2) || (D.r(strB, str2, false) && (D.k(str2, "/", false) || strB.charAt(str2.length()) == '/'))) {
                        if (!c5083l.f || url.j) {
                            arrayList2.add(c5083l);
                        }
                    }
                }
            }
        }
        if (!arrayList.isEmpty()) {
            SharedPreferences.Editor editorEdit = this.c.edit();
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                a aVar2 = (a) it2.next();
                set.remove(aVar2);
                editorEdit.remove(aVar2.a());
            }
            editorEdit.apply();
        }
        return arrayList2;
    }
}
