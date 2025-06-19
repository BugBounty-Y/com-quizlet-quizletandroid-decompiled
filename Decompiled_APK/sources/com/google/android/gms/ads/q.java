package com.google.android.gms.ads;

import android.os.Bundle;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.client.s0;
import com.google.android.gms.ads.internal.client.zzv;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class q {
    public final s0 a;
    public final ArrayList b = new ArrayList();
    public final j c;

    public q(s0 s0Var) {
        this.a = s0Var;
        if (s0Var != null) {
            try {
                List<zzv> listI = s0Var.i();
                if (listI != null) {
                    for (zzv zzvVar : listI) {
                        j jVar = zzvVar != null ? new j(zzvVar) : null;
                        if (jVar != null) {
                            this.b.add(jVar);
                        }
                    }
                }
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.f("Could not forward getAdapterResponseInfo to ResponseInfo.", e);
            }
        }
        s0 s0Var2 = this.a;
        if (s0Var2 == null) {
            return;
        }
        try {
            zzv zzvVarF = s0Var2.f();
            if (zzvVarF != null) {
                this.c = new j(zzvVarF);
            }
        } catch (RemoteException e2) {
            com.google.android.gms.ads.internal.util.client.i.f("Could not forward getLoadedAdapterResponse to ResponseInfo.", e2);
        }
    }

    public final JSONObject a() throws JSONException {
        String strZzi;
        Bundle bundleZze;
        JSONObject jSONObject = new JSONObject();
        s0 s0Var = this.a;
        String strH = null;
        if (s0Var != null) {
            try {
                strZzi = s0Var.zzi();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.f("Could not forward getResponseId to ResponseInfo.", e);
            }
        } else {
            strZzi = null;
        }
        if (strZzi == null) {
            jSONObject.put("Response ID", "null");
        } else {
            jSONObject.put("Response ID", strZzi);
        }
        if (s0Var != null) {
            try {
                strH = s0Var.h();
            } catch (RemoteException e2) {
                com.google.android.gms.ads.internal.util.client.i.f("Could not forward getMediationAdapterClassName to ResponseInfo.", e2);
            }
        }
        if (strH == null) {
            jSONObject.put("Mediation Adapter Class Name", "null");
        } else {
            jSONObject.put("Mediation Adapter Class Name", strH);
        }
        JSONArray jSONArray = new JSONArray();
        Iterator it2 = this.b.iterator();
        while (it2.hasNext()) {
            jSONArray.put(((j) it2.next()).a());
        }
        jSONObject.put("Adapter Responses", jSONArray);
        j jVar = this.c;
        if (jVar != null) {
            jSONObject.put("Loaded Adapter Response", jVar.a());
        }
        if (s0Var != null) {
            try {
                bundleZze = s0Var.zze();
            } catch (RemoteException e3) {
                com.google.android.gms.ads.internal.util.client.i.f("Could not forward getResponseExtras to ResponseInfo.", e3);
            }
        } else {
            bundleZze = new Bundle();
        }
        if (bundleZze != null) {
            jSONObject.put("Response Extras", C1614q.f.a.h(bundleZze));
        }
        return jSONObject;
    }

    public final String toString() {
        try {
            return a().toString(2);
        } catch (JSONException unused) {
            return "Error forming toString output.";
        }
    }
}
