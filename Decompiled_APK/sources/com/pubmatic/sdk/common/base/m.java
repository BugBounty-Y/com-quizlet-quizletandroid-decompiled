package com.pubmatic.sdk.common.base;

import android.os.Trace;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.models.a;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class m implements com.pubmatic.sdk.common.network.d, o, a, com.pubmatic.sdk.common.network.e {

    @NonNull
    private final n a;

    @NonNull
    private final p b;

    @NonNull
    private final b c;

    @NonNull
    private final com.pubmatic.sdk.common.network.g d;
    private k e;
    private com.pubmatic.sdk.common.network.l f;
    private l g;

    public m(@NonNull n nVar, @NonNull p pVar, @NonNull b bVar, @NonNull com.pubmatic.sdk.common.network.g gVar) {
        this.a = nVar;
        this.d = gVar;
        this.c = bVar;
        bVar.setListener(this);
        this.b = pVar;
        pVar.setListener(this);
    }

    private void a(@NonNull com.pubmatic.sdk.common.h hVar) {
        k kVar = this.e;
        if (kVar != null) {
            kVar.onError(hVar);
        }
    }

    @Override // com.pubmatic.sdk.common.base.a
    public void adBuilderOnSuccess(@NonNull com.pubmatic.sdk.common.models.a aVar) {
        k kVar = this.e;
        if (kVar != null) {
            kVar.onSuccess(aVar);
        }
    }

    public void cancel() {
        this.d.cancelRequest(String.valueOf(this.a.hashCode()));
    }

    public com.pubmatic.sdk.common.network.l getNetworkResult() {
        return this.f;
    }

    @Override // com.pubmatic.sdk.common.network.d
    public void onFailure(@NonNull com.pubmatic.sdk.common.h hVar) {
        POBLog.debug("POBCommunicator", "Failed to receive an Ad response from server - %s", hVar.getErrorMessage());
        a(hVar);
    }

    @Override // com.pubmatic.sdk.common.network.e
    public void onResult(com.pubmatic.sdk.common.network.l lVar) {
        this.f = lVar;
    }

    @Override // com.pubmatic.sdk.common.base.o
    public void parserOnError(@NonNull com.pubmatic.sdk.common.h hVar) {
        a(hVar);
    }

    @Override // com.pubmatic.sdk.common.base.o
    public void parserOnSuccess(@NonNull com.pubmatic.sdk.common.models.a aVar) {
        this.c.build(new a.C0010a(aVar).build());
    }

    public void requestAd() {
        com.pubmatic.sdk.common.network.a aVarBuild = this.a.build();
        if (aVarBuild == null) {
            a(new com.pubmatic.sdk.common.h(1001, "Exception occurred while preparing this ad request"));
            return;
        }
        Trace.endSection();
        Trace.beginSection("POB Network Call");
        POBLog.debug("POBCommunicator", "Sending an Ad request - : %s", aVarBuild.toString());
        this.d.sendJSONRequest(aVarBuild, this, this);
    }

    public void setListener(k kVar) {
        this.e = kVar;
    }

    public void setPOBErrorCustomisationListener(l lVar) {
    }

    @Override // com.pubmatic.sdk.common.network.d
    public void onSuccess(JSONObject jSONObject) {
        if (jSONObject != null) {
            POBLog.debug("POBCommunicator", "Successfully received Ad response from server - %s", jSONObject.toString());
        }
        Trace.endSection();
        Trace.beginSection("POB Response Parsing");
        this.b.parse(jSONObject);
    }
}
