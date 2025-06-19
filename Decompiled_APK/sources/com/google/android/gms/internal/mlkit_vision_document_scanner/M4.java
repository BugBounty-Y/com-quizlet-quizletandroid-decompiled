package com.google.android.gms.internal.mlkit_vision_document_scanner;

import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class M4 {
    public static final /* synthetic */ int a = 0;

    public static com.google.android.material.floatingactionbutton.c a(JSONObject json) {
        Intrinsics.checkNotNullParameter(json, "json");
        com.google.mlkit.common.sdkinternal.b bVar = com.perimeterx.mobile_sdk.web_view_interception.d.a;
        String type = json.getString("captchaType");
        Intrinsics.checkNotNullExpressionValue(type, "getString(...)");
        bVar.getClass();
        Intrinsics.checkNotNullParameter(type, "type");
        if (!Intrinsics.b(type, com.perimeterx.mobile_sdk.web_view_interception.d.b.a()) && !Intrinsics.b(type, com.perimeterx.mobile_sdk.web_view_interception.d.c.a())) {
            Intrinsics.b(type, com.perimeterx.mobile_sdk.web_view_interception.d.d.a());
        }
        com.google.mlkit.common.internal.model.a aVar = com.perimeterx.mobile_sdk.web_view_interception.c.a;
        String stage = json.getString("captchaStage");
        Intrinsics.checkNotNullExpressionValue(stage, "getString(...)");
        aVar.getClass();
        Intrinsics.checkNotNullParameter(stage, "stage");
        com.perimeterx.mobile_sdk.web_view_interception.c cVar = com.perimeterx.mobile_sdk.web_view_interception.c.b;
        if (!Intrinsics.b(stage, cVar.a())) {
            cVar = com.perimeterx.mobile_sdk.web_view_interception.c.c;
            if (!Intrinsics.b(stage, cVar.a())) {
                cVar = com.perimeterx.mobile_sdk.web_view_interception.c.d;
                if (!Intrinsics.b(stage, cVar.a())) {
                    cVar = com.perimeterx.mobile_sdk.web_view_interception.c.e;
                    if (!Intrinsics.b(stage, cVar.a())) {
                        cVar = null;
                    }
                }
            }
        }
        if (cVar != null) {
            return new com.google.android.material.floatingactionbutton.c(cVar);
        }
        return null;
    }
}
