package com.perimeterx.mobile_sdk.doctor_app.model;

import androidx.compose.ui.node.B;
import com.amazon.device.ads.DtbConstants;
import com.perimeterx.mobile_sdk.PerimeterX;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class d {
    public static final SimpleDateFormat h = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
    public final String a;
    public Date b;
    public boolean c;
    public boolean d;
    public b e;
    public i f;
    public com.perimeterx.mobile_sdk.doctor_app.f g;

    public d() {
        this.a = B.f("toString(...)");
    }

    public final JSONObject a() throws JSONException {
        String str;
        JSONObject jSONObject = new JSONObject();
        Date date = this.b;
        if (date != null) {
            jSONObject.putOpt("date", h.format(date));
        }
        jSONObject.putOpt("uuid", this.a);
        jSONObject.put("startOnLaunchOK", this.c);
        jSONObject.put("vidOK", this.d);
        b bVar = this.e;
        if (bVar != null) {
            JSONObject jSONObject2 = new JSONObject();
            jSONObject2.put("headersOK", bVar.a);
            jSONObject2.put("responseHandlerCalled", bVar.b);
            jSONObject2.put("mobileChallengeOK", bVar.c);
            jSONObject2.put("challengeShown", bVar.d);
            jSONObject2.put("challengeDismissed", bVar.e);
            jSONObject2.put("callbacksCalled", bVar.f);
            jSONObject2.put("deviceFPWasSent", bVar.g);
            jSONObject2.put("userIdReported", bVar.h);
            jSONObject2.put("outgoingURLsReported", bVar.i);
            jSONObject2.put("additionalDataSet", bVar.j);
            jSONObject2.put("additionalDataReported", bVar.k);
            jSONObject.putOpt("nativeSummary", jSONObject2.toString());
        }
        i iVar = this.f;
        if (iVar != null) {
            JSONObject jSONObject3 = new JSONObject();
            jSONObject3.put("webViewSynced", iVar.a);
            jSONObject3.put("challengeShown", iVar.b);
            jSONObject3.put("challengeDismissed", iVar.c);
            jSONObject3.put("mobileDataSet", iVar.d);
            jSONObject.putOpt("webViewSummary", jSONObject3.toString());
        }
        com.perimeterx.mobile_sdk.doctor_app.f fVar = this.g;
        if (fVar != null) {
            int iOrdinal = fVar.ordinal();
            if (iOrdinal == 0) {
                str = "bot defender";
            } else {
                if (iOrdinal != 1) {
                    throw new NoWhenBranchMatchedException();
                }
                str = "account defender";
            }
            jSONObject.putOpt("product", str);
        }
        jSONObject.put("doctorVersion", DtbConstants.APS_ADAPTER_VERSION_2);
        jSONObject.put("sdkVersion", PerimeterX.INSTANCE.sdkVersion());
        return jSONObject;
    }

    public d(String str, Date date, boolean z, boolean z2, b bVar, i iVar, com.perimeterx.mobile_sdk.doctor_app.f fVar) {
        Intrinsics.checkNotNullExpressionValue(UUID.randomUUID().toString(), "toString(...)");
        this.a = str;
        this.b = date;
        this.c = z;
        this.d = z2;
        this.e = bVar;
        this.f = iVar;
        this.g = fVar;
    }
}
