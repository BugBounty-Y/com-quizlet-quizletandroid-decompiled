package com.google.android.gms.internal.mlkit_vision_document_scanner;

import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.w4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3752w4 {
    public static final /* synthetic */ int a = 0;

    public static com.perimeterx.mobile_sdk.doctor_app.model.b a(JSONObject json) throws JSONException {
        Intrinsics.checkNotNullParameter(json, "json");
        try {
            boolean z = json.getBoolean("headersOK");
            boolean z2 = json.getBoolean("responseHandlerCalled");
            boolean z3 = json.getBoolean("mobileChallengeOK");
            boolean z4 = json.getBoolean("challengeShown");
            boolean z5 = json.getBoolean("challengeDismissed");
            boolean z6 = json.getBoolean("callbacksCalled");
            boolean z7 = json.getBoolean("deviceFPWasSent");
            boolean z8 = json.getBoolean("userIdReported");
            boolean z9 = json.getBoolean("outgoingURLsReported");
            boolean z10 = json.getBoolean("additionalDataSet");
            boolean z11 = json.getBoolean("additionalDataReported");
            com.perimeterx.mobile_sdk.doctor_app.model.b bVar = new com.perimeterx.mobile_sdk.doctor_app.model.b();
            bVar.a = z;
            bVar.b = z2;
            bVar.c = z3;
            bVar.d = z4;
            bVar.e = z5;
            bVar.f = z6;
            bVar.g = z7;
            bVar.h = z8;
            bVar.i = z9;
            bVar.j = z10;
            bVar.k = z11;
            return bVar;
        } catch (Exception unused) {
            return null;
        }
    }
}
