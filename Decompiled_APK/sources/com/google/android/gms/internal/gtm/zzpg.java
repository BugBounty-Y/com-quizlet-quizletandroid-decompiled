package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.api.Status;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
final class zzpg implements zzpf {
    @Override // com.google.android.gms.internal.gtm.zzpf
    public final zzpl zza(byte[] bArr) throws zzoy, JSONException {
        if (bArr == null) {
            throw new zzoy("Cannot parse a null byte[]");
        }
        if (bArr.length == 0) {
            throw new zzoy("Cannot parse a 0 length byte[]");
        }
        try {
            Object obj = new JSONObject(new String(bArr)).get("resource");
            if (!(obj instanceof JSONObject)) {
                throw new zzoy("Resource map not found");
            }
            JSONObject jSONObject = (JSONObject) obj;
            zzpx zzpxVar = new zzpx();
            zzpxVar.zzc(jSONObject.optString("version"));
            JSONArray jSONArray = jSONObject.getJSONArray("macros");
            ArrayList arrayList = new ArrayList();
            for (int i = 0; i < jSONArray.length(); i++) {
                arrayList.add(jSONArray.getJSONObject(i).getString("instance_name"));
            }
            List listZzd = zzoz.zzd(jSONObject.getJSONArray("tags"), arrayList);
            List listZzd2 = zzoz.zzd(jSONObject.getJSONArray("predicates"), arrayList);
            Iterator it2 = zzoz.zzd(jSONObject.getJSONArray("macros"), arrayList).iterator();
            while (it2.hasNext()) {
                zzpxVar.zza((zzqb) it2.next());
            }
            JSONArray jSONArray2 = jSONObject.getJSONArray("rules");
            for (int i2 = 0; i2 < jSONArray2.length(); i2++) {
                zzpxVar.zzb(zzoz.zzb(jSONArray2.getJSONArray(i2), listZzd, listZzd2));
            }
            zzpy zzpyVarZzd = zzpxVar.zzd();
            zzhi.zzd("The container was successfully parsed from the resource");
            return new zzpl(Status.e, 0, new zzpk(null, null, zzpyVarZzd, 0L), zzpi.zzb.zza(bArr).zzc());
        } catch (zzoy unused) {
            throw new zzoy("The resource data is invalid. The container cannot be extracted from the JSON data");
        } catch (JSONException unused2) {
            throw new zzoy("The resource data is corrupted. The container cannot be extracted from the JSON data");
        }
    }
}
