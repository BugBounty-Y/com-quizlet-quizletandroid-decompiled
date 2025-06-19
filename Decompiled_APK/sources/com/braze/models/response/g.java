package com.braze.models.response;

import com.braze.managers.o0;
import com.braze.models.inappmessage.InAppMessageBase;
import com.braze.support.JsonUtils;
import java.util.ArrayList;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class g extends a {
    public final JSONObject c;
    public final d d;
    public final i e;
    public final c f;
    public final InAppMessageBase g;
    public final ArrayList h;
    public final m i;
    public final ArrayList j;
    public final JSONArray k;
    public final String l;
    public final JSONArray m;
    public final long n;
    public final JSONObject o;
    public final o0 p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Removed duplicated region for block: B:43:0x013e  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0143  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x014a  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0153  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x015a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public g(com.braze.requests.n r14, com.braze.communication.d r15, com.braze.managers.C1500m r16) {
        /*
            Method dump skipped, instructions count: 358
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.models.response.g.<init>(com.braze.requests.n, com.braze.communication.d, com.braze.managers.m):void");
    }

    public static final String a(g gVar) {
        return "Encountered Exception processing Content Cards response: " + gVar.c;
    }

    public static final String b(g gVar) {
        return "Found " + gVar.h.size() + " triggered actions in server response.";
    }

    public static final String a(JSONObject jSONObject) {
        return "Got server config: " + JsonUtils.getPrettyPrintedString(jSONObject);
    }

    public static final String b(JSONObject jSONObject) {
        return assistantMode.refactored.a.j("Encountered Exception processing server config: ", jSONObject);
    }
}
