package com.google.android.gms.internal.mlkit_vision_common;

import com.facebook.FacebookException;
import com.facebook.FacebookRequestError;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

/* loaded from: classes2.dex */
public abstract class G {
    public static final /* synthetic */ int a = 0;

    public static ArrayList a(AbstractList requests, HttpURLConnection httpURLConnection, FacebookException facebookException) {
        Intrinsics.checkNotNullParameter(requests, "requests");
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(requests, 10));
        Iterator it2 = requests.iterator();
        while (it2.hasNext()) {
            arrayList.add(new com.facebook.w((com.facebook.t) it2.next(), httpURLConnection, new FacebookRequestError(facebookException)));
        }
        return arrayList;
    }

    /* JADX WARN: Removed duplicated region for block: B:47:0x00e7 A[Catch: JSONException -> 0x011e, TryCatch #0 {JSONException -> 0x011e, blocks: (B:5:0x001c, B:7:0x0022, B:9:0x002c, B:11:0x0030, B:14:0x003d, B:16:0x0048, B:19:0x0052, B:22:0x005c, B:25:0x0064, B:27:0x006a, B:30:0x0074, B:33:0x007e, B:47:0x00e7, B:36:0x0091, B:39:0x009e, B:41:0x00a7, B:45:0x00bd, B:53:0x00fd, B:55:0x0105, B:56:0x010b), top: B:94:0x001c }] */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00f4  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x0121  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x01af  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.facebook.w b(com.facebook.t r23, java.net.HttpURLConnection r24, java.lang.Object r25, java.lang.Object r26) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 528
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.G.b(com.facebook.t, java.net.HttpURLConnection, java.lang.Object, java.lang.Object):com.facebook.w");
    }

    public static ArrayList c(InputStream inputStream, HttpURLConnection httpURLConnection, com.facebook.v requests) throws Throwable {
        Object obj;
        Intrinsics.checkNotNullParameter(requests, "requests");
        String responseString = com.facebook.internal.J.L(inputStream);
        com.google.mlkit.common.sdkinternal.model.a aVar = com.facebook.internal.A.c;
        com.google.mlkit.common.sdkinternal.model.a.w(com.facebook.y.c, "Response", "Response (raw)\n  Size: %d\n  Response:\n%s\n", Integer.valueOf(responseString.length()), responseString);
        Intrinsics.checkNotNullParameter(responseString, "responseString");
        Intrinsics.checkNotNullParameter(requests, "requests");
        Object resultObject = new JSONTokener(responseString).nextValue();
        Intrinsics.checkNotNullExpressionValue(resultObject, "resultObject");
        int size = requests.c.size();
        ArrayList arrayList = new ArrayList(size);
        if (size == 1) {
            com.facebook.t tVar = (com.facebook.t) requests.get(0);
            try {
                JSONObject jSONObject = new JSONObject();
                jSONObject.put("body", resultObject);
                jSONObject.put("code", httpURLConnection.getResponseCode());
                JSONArray jSONArray = new JSONArray();
                jSONArray.put(jSONObject);
                obj = jSONArray;
            } catch (IOException e) {
                arrayList.add(new com.facebook.w(tVar, httpURLConnection, new FacebookRequestError(e)));
            } catch (JSONException e2) {
                arrayList.add(new com.facebook.w(tVar, httpURLConnection, new FacebookRequestError(e2)));
            }
        } else {
            obj = resultObject;
        }
        if (obj instanceof JSONArray) {
            JSONArray jSONArray2 = (JSONArray) obj;
            if (jSONArray2.length() == size) {
                int length = jSONArray2.length();
                for (int i = 0; i < length; i++) {
                    com.facebook.t tVar2 = (com.facebook.t) requests.get(i);
                    try {
                        Object obj2 = ((JSONArray) obj).get(i);
                        Intrinsics.checkNotNullExpressionValue(obj2, "obj");
                        arrayList.add(b(tVar2, httpURLConnection, obj2, resultObject));
                    } catch (FacebookException e3) {
                        arrayList.add(new com.facebook.w(tVar2, httpURLConnection, new FacebookRequestError(e3)));
                    } catch (JSONException e4) {
                        arrayList.add(new com.facebook.w(tVar2, httpURLConnection, new FacebookRequestError(e4)));
                    }
                }
                com.google.mlkit.common.sdkinternal.model.a aVar2 = com.facebook.internal.A.c;
                com.google.mlkit.common.sdkinternal.model.a.w(com.facebook.y.a, "Response", "Response\n  Id: %s\n  Size: %d\n  Responses:\n%s\n", requests.b, Integer.valueOf(responseString.length()), arrayList);
                return arrayList;
            }
        }
        throw new FacebookException("Unexpected number of results");
    }
}
