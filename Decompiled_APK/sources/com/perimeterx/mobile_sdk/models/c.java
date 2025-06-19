package com.perimeterx.mobile_sdk.models;

import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class c {
    public final String a;
    public final String b;
    public final ArrayList c;
    public final b d;
    public final boolean e;

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    public c(JSONObject response) throws JSONException, NumberFormatException {
        Intrinsics.checkNotNullParameter(response, "response");
        this.c = new ArrayList();
        Object obj = response.get("do");
        Intrinsics.e(obj, "null cannot be cast to non-null type org.json.JSONArray");
        JSONArray jSONArray = (JSONArray) obj;
        int length = jSONArray.length();
        for (int i = 0; i < length; i++) {
            Object obj2 = jSONArray.get(i);
            Intrinsics.e(obj2, "null cannot be cast to non-null type kotlin.String");
            List components = StringsKt__StringsKt.split$default((String) obj2, new String[]{"|"}, false, 0, 6, null);
            if (components.size() > 1) {
                String str = (String) components.get(0);
                String str2 = (String) components.get(1);
                switch (str.hashCode()) {
                    case 113870:
                        if (str.equals("sid")) {
                            this.a = str2;
                            break;
                        } else {
                            break;
                        }
                    case 116753:
                        if (str.equals("vid")) {
                            this.b = str2;
                            break;
                        } else {
                            break;
                        }
                    case 3000930:
                        if (str.equals("appc")) {
                            Intrinsics.checkNotNullParameter(components, "components");
                            b bVar = (components.size() < 2 || !Intrinsics.b(components.get(1), "2") || components.size() < 10) ? null : new b(components);
                            if (bVar != null) {
                                this.d = bVar;
                                break;
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    case 3016153:
                        if (str.equals("bake") && components.size() > 5) {
                            String str3 = (String) components.get(1);
                            String str4 = (String) components.get(3);
                            Integer.parseInt((String) components.get(5));
                            this.c.add(new d(str3, str4));
                            break;
                        } else {
                            break;
                        }
                        break;
                    case 3092822:
                        if (str.equals("dsdk")) {
                            this.e = Boolean.parseBoolean(str2);
                            break;
                        } else {
                            break;
                        }
                }
            }
        }
    }
}
