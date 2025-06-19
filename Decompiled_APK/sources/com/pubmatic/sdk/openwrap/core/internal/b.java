package com.pubmatic.sdk.openwrap.core.internal;

import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.base.o;
import com.pubmatic.sdk.common.base.p;
import com.pubmatic.sdk.common.h;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.models.a;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class b implements p {
    private o a;

    @Override // com.pubmatic.sdk.common.base.p
    public void parse(JSONObject jSONObject) {
        POBLog.debug("POBResponseParser", "response :%s", jSONObject);
        if (jSONObject != null) {
            a.C0010a c0010a = new a.C0010a(jSONObject);
            o oVar = this.a;
            if (oVar != null) {
                oVar.parserOnSuccess(c0010a.build());
                return;
            }
            return;
        }
        POBLog.error("POBResponseParser", "Listener not set to respond back for invalid input", new Object[0]);
        o oVar2 = this.a;
        if (oVar2 != null) {
            oVar2.parserOnError(new h(1007, "Listener not set to respond back for invalid input"));
        }
    }

    @Override // com.pubmatic.sdk.common.base.p
    public void setListener(@NonNull o oVar) {
        this.a = oVar;
    }
}
