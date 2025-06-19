package com.facebook.appevents;

import androidx.compose.animation.d0;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.util.HashSet;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class e implements Serializable {
    public static final HashSet f = new HashSet();
    public final JSONObject a;
    public final JSONObject b;
    public final boolean c;
    public final boolean d;
    public final String e;

    /* JADX WARN: Removed duplicated region for block: B:32:0x00a2  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x00b8 A[PHI: r11
  0x00b8: PHI (r11v12 java.lang.String) = (r11v1 java.lang.String), (r11v1 java.lang.String), (r11v11 java.lang.String) binds: [B:37:0x00b6, B:57:0x00fc, B:54:0x00f8] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public e(java.lang.String r7, java.lang.String r8, java.lang.Double r9, android.os.Bundle r10, boolean r11, boolean r12, java.util.UUID r13, com.facebook.appevents.q r14) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 814
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.e.<init>(java.lang.String, java.lang.String, java.lang.Double, android.os.Bundle, boolean, boolean, java.util.UUID, com.facebook.appevents.q):void");
    }

    private final Object writeReplace() throws ObjectStreamException {
        String string = this.a.toString();
        Intrinsics.checkNotNullExpressionValue(string, "jsonObject.toString()");
        String string2 = this.b.toString();
        Intrinsics.checkNotNullExpressionValue(string2, "operationalJsonObject.toString()");
        return new d(string, string2, this.c, this.d);
    }

    public final String toString() {
        JSONObject jSONObject = this.a;
        return d0.s(new Object[]{jSONObject.optString("_eventName"), Boolean.valueOf(this.c), jSONObject.toString()}, 3, "\"%s\", implicit: %b, json: %s", "format(format, *args)");
    }

    public e(String str, String str2, boolean z, boolean z2) {
        JSONObject jSONObject = new JSONObject(str);
        this.a = jSONObject;
        this.b = new JSONObject(str2);
        this.c = z;
        String strOptString = jSONObject.optString("_eventName");
        Intrinsics.checkNotNullExpressionValue(strOptString, "jsonObject.optString(Con…nts.EVENT_NAME_EVENT_KEY)");
        this.e = strOptString;
        this.d = z2;
    }
}
