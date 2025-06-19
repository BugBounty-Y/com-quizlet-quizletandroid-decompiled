package com.onetrust.otpublishers.headless.Internal.authenticatedconsent;

import android.content.Context;
import androidx.annotation.NonNull;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import java.time.Instant;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class a {
    public final Context a;

    public a(@NonNull Context context) {
        this.a = context;
    }

    public static boolean b(long j, JSONObject jSONObject) throws JSONException {
        long epochMilli;
        if (jSONObject.has("preferences")) {
            JSONArray jSONArray = jSONObject.getJSONArray("preferences");
            if (jSONArray.length() != 0) {
                long j2 = 0;
                for (int i = 0; i < jSONArray.length(); i++) {
                    JSONObject jSONObject2 = jSONArray.getJSONObject(i);
                    if (jSONObject2.has("consentDate")) {
                        String string = jSONObject2.getString("consentDate");
                        epochMilli = ("null".equalsIgnoreCase(string) || com.onetrust.otpublishers.headless.Internal.a.j(string)) ? -1L : Instant.parse(string).toEpochMilli();
                    } else {
                        epochMilli = 0;
                    }
                    if (epochMilli > j2) {
                        j2 = epochMilli;
                    }
                }
                OTLogger.c("authenticatedConsentFlow", 3, "recent consented time stamp = " + j2);
                if (j > j2) {
                    return true;
                }
            }
        }
        return false;
    }

    /* JADX WARN: Can't wrap try/catch for region: R(13:61|(1:63)(1:64)|65|(3:67|68|(0))|69|86|(1:88)(1:89)|(1:91)|193|92|(1:94)(1:98)|99|(4:191|101|105|(0))(3:104|105|(0))) */
    /* JADX WARN: Code restructure failed: missing block: B:96:0x024b, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:97:0x024c, code lost:
    
        com.google.android.gms.measurement.internal.Z.p("error while getting profile data json, err: ", r0, "OneTrust", 6);
     */
    /* JADX WARN: Removed duplicated region for block: B:104:0x0270  */
    /* JADX WARN: Removed duplicated region for block: B:181:0x041b  */
    /* JADX WARN: Removed duplicated region for block: B:191:0x0261 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:219:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00bf  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x012f  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x022b  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x0236  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x023a  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x0245 A[Catch: JSONException -> 0x024b, TRY_LEAVE, TryCatch #4 {JSONException -> 0x024b, blocks: (B:92:0x023b, B:94:0x0245), top: B:193:0x023b }] */
    /* JADX WARN: Removed duplicated region for block: B:98:0x0254  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a() {
        /*
            Method dump skipped, instructions count: 1093
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.authenticatedconsent.a.a():void");
    }
}
