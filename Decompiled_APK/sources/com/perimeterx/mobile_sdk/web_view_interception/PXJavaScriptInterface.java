package com.perimeterx.mobile_sdk.web_view_interception;

import android.webkit.JavascriptInterface;
import androidx.annotation.Keep;
import com.google.android.gms.internal.mlkit_vision_document_scanner.M4;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;

@Keep
@Metadata
/* loaded from: classes2.dex */
public final class PXJavaScriptInterface {

    @NotNull
    private final e _internal = new e();

    @NotNull
    public final e get_internal$PerimeterX_release() {
        return this._internal;
    }

    @JavascriptInterface
    public final void handleEvent(@NotNull String eventJson) {
        Intrinsics.checkNotNullParameter(eventJson, "eventJson");
        e eVar = this._internal;
        eVar.getClass();
        Intrinsics.checkNotNullParameter(eventJson, "eventJson");
        try {
            com.google.android.material.floatingactionbutton.c cVarA = M4.a(new JSONObject(eventJson));
            if (cVarA != null) {
                com.google.android.material.floatingactionbutton.c cVar = eVar.b;
                if (cVar == null || ((c) cVar.b) != ((c) cVarA.b)) {
                    eVar.b = cVarA;
                    f fVar = eVar.a;
                    if (fVar != null) {
                        fVar.a(cVarA);
                        Unit unit = Unit.a;
                    }
                }
            }
        } catch (Exception unused) {
        }
    }
}
